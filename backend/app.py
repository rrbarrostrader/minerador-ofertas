"""API + painel do minerador de ofertas (Ad Library).

Local:   python app.py           (usa o mesmo Postgres do Neon via DATABASE_URL)
Vercel:  api/index.py importa este `app`

  /api/*  consumido pela extensão (auth por Bearer token)
  /       painel web (auth por sessão)
"""

from __future__ import annotations

import os
import re
import secrets
import time
from datetime import datetime, timezone
from functools import wraps

import psycopg
from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session, url_for)
from psycopg.types.json import Json

import autotermos
import enrich
import ideias
import lowticket
from lowticket import (COTACAO_BRL, LOW_TICKET_MAX, NAO_VENDE,
                       LOW_TICKET_DIAS_MIN, LOW_TICKET_CRIATIVOS_MIN)
import midias
from db import confere_senha, get_db, novo_token, user_por_token
from gateways import e_gateway, tipo_de

# Destino que não é página de venda: perfil, conversa, loja de app. Serve ao
# filtro "só quem vende" — em low ticket, link de bio é ruído.
# Com o Blob suspenso por cota, as URLs dele devolvem 403 até na leitura: toda
# capa copiada vira quadro vazio. MINERADOR_BLOB=0 faz o painel ignorar o que
# está lá e usar og:image do destino ou a URL da CDN da Meta.
BLOB_ATIVO = os.getenv("MINERADOR_BLOB", "1") != "0"

def midia_viva(url: str) -> str:
    """URL de mídia que ainda serve. Com o Blob suspenso, o que está lá devolve
    403 até na leitura — mas a miniatura em /capa/<id> vem do nosso banco e
    continua valendo, então ela não pode cair junto."""
    url = url or ""
    if not url:
        return ""
    if url.startswith("/capa/"):
        return url
    return url if BLOB_ATIVO else ""


RE_OE = re.compile(r"[?&]oe=([0-9A-Fa-f]{8})")


def meta_viva(url: str) -> str:
    """URL da CDN da Meta só enquanto a assinatura vale (`oe=` é o vencimento
    em hex). Vencida ela só devolve 403: melhor cair direto na próxima reserva
    do que pintar quadro quebrado."""
    url = url or ""
    m = RE_OE.search(url)
    if m and int(m.group(1), 16) < time.time():
        return ""
    return url


app = Flask(__name__)

_segredo = os.getenv("MINERADOR_SECRET")
if not _segredo:
    if os.getenv("VERCEL"):
        raise RuntimeError("Defina MINERADOR_SECRET nas variáveis de ambiente do projeto.")
    _segredo = secrets.token_hex(32)  # dev: sessão morre a cada restart, tudo bem
app.secret_key = _segredo

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.getenv("VERCEL")),
    JSON_SORT_KEYS=False,
)


# ---------------------------------------------------------------- infraestrutura

def _motivo_do_banco(e: Exception) -> str:
    """Traduz a falha do Postgres. O erro cru vira 500 e não diz nada a quem usa."""
    texto = str(e)
    if "transfer quota" in texto or "exceeded" in texto:
        return ("O banco atingiu a cota do plano gratuito (transferência de dados) "
                "e está recusando conexões. Nada foi perdido — volta quando a cota "
                "reabrir ou quando o plano for alterado.")
    if "Cannot assign requested address" in texto or "could not connect" in texto:
        return "Sem conexão com o banco no momento."
    return "Banco indisponível: " + texto.splitlines()[0][:160]


@app.errorhandler(psycopg.OperationalError)
def banco_fora(e):
    """503 com explicação, em vez de 500 sem pista — para o painel e para a
    extensão saberem que o problema não é a pesquisa deles."""
    motivo = _motivo_do_banco(e)
    if request.path.startswith(("/api/", "/dados/")):
        return jsonify({"erro": motivo, "banco_fora": True}), 503
    return render_template("indisponivel.html", motivo=motivo), 503


@app.after_request
def cors(resp):
    """A extensão chama a API de uma origem chrome-extension://.
    Sem cookie envolvido — autenticação é só o Bearer token."""
    if request.path.startswith("/api/"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/api/<path:_qualquer>", methods=["OPTIONS"])
def preflight(_qualquer):
    return ("", 204)


def precisa_token(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        user = user_por_token(token)
        if not user:
            return jsonify({"erro": "nao autenticado"}), 401
        g.user = user
        return f(*a, **kw)
    return wrapper


def precisa_sessao(f):
    @wraps(f)
    def wrapper(*a, **kw):
        uid = session.get("uid")
        if not uid:
            return redirect(url_for("login_page"))
        conn = get_db()
        row = conn.execute("SELECT * FROM usuarios WHERE id = %s", (uid,)).fetchone()
        conn.close()
        if not row:
            session.clear()
            return redirect(url_for("login_page"))
        g.user = dict(row)
        return f(*a, **kw)
    return wrapper


def dias_desde(epoch) -> int:
    if not epoch:
        return 0
    try:
        delta = datetime.now(timezone.utc) - datetime.fromtimestamp(int(epoch), tz=timezone.utc)
        return max(0, delta.days)
    except (ValueError, OSError, TypeError):
        return 0


# ---------------------------------------------------------------- auth

@app.post("/api/login")
def api_login():
    dados = request.get_json(silent=True) or {}
    conn = get_db()
    row = conn.execute("SELECT * FROM usuarios WHERE username = %s",
                       (str(dados.get("username", "")).strip(),)).fetchone()
    conn.close()
    if not row or not confere_senha(str(dados.get("password", "")), row["password_hash"]):
        return jsonify({"erro": "usuario ou senha invalidos"}), 401
    return jsonify({
        "token": novo_token(row["id"]),
        "usuario": row["username"],
        "plano": row["plano"],
        "usos_restantes": row["usos_restantes"],
    })


@app.get("/api/me")
@precisa_token
def api_me():
    conn = get_db()
    row = conn.execute("SELECT * FROM usuarios WHERE id = %s", (g.user["id"],)).fetchone()
    total = conn.execute("SELECT COUNT(*) AS c FROM anuncios WHERE user_id = %s",
                         (g.user["id"],)).fetchone()["c"]
    conn.close()
    return jsonify({
        "usuario": row["username"], "plano": row["plano"],
        "usos_restantes": row["usos_restantes"], "anuncios_salvos": total,
        "dashboard": request.url_root.rstrip("/"),
    })


# ---------------------------------------------------------------- ingestão

@app.post("/api/anuncios")
@precisa_token
def api_anuncios():
    dados = request.get_json(silent=True) or {}
    ads = dados.get("anuncios") or []
    termo = str(dados.get("termo", ""))[:200]
    pais = str(dados.get("pais", "BR"))[:5]
    if not isinstance(ads, list):
        return jsonify({"erro": "anuncios deve ser lista"}), 400

    linhas, urls, ids = [], set(), []
    descartados = 0
    for ad in ads[:2000]:
        if not isinstance(ad, dict) or not ad.get("ad_archive_id"):
            continue
        # Só oferta de entrada entra: sem link, app, perfil e WhatsApp nunca
        # vão ter preço e checkout para provar.
        if not lowticket.link_pode_ser_low(ad.get("link_url")):
            descartados += 1
            continue
        link = (ad.get("link_url") or "")[:1000]
        ids.append(str(ad["ad_archive_id"]))
        linhas.append((
            g.user["id"], str(ad["ad_archive_id"]), str(ad.get("page_id") or ""),
            (ad.get("page_name") or "")[:250], 1 if ad.get("is_active") else 0,
            ad.get("start_date"), ad.get("end_date"), dias_desde(ad.get("start_date")),
            (ad.get("plataformas") or "")[:120], (ad.get("cta_text") or "")[:80],
            link, (ad.get("titulo") or "")[:300], (ad.get("legenda") or "")[:300],
            (ad.get("texto") or "")[:1500], (ad.get("midia") or "")[:40],
            (ad.get("midia_url") or "")[:1000], (ad.get("midia_sd") or "")[:1000],
            (ad.get("midia_poster") or "")[:1000],
            int(ad.get("variacoes") or 1), termo, pais,
        ))
        if link.startswith("http"):
            urls.add(link)

    conn = get_db()
    with conn:
        ja_tinha = set()
        if ids:
            ja_tinha = {r["ad_archive_id"] for r in conn.execute(
                "SELECT ad_archive_id FROM anuncios WHERE user_id = %s AND ad_archive_id = ANY(%s)",
                (g.user["id"], ids)).fetchall()}

        if linhas:
            conn.cursor().executemany("""
                INSERT INTO anuncios (user_id, ad_archive_id, page_id, page_name, is_active,
                    start_date, end_date, dias_ativo, plataformas, cta_text, link_url,
                    titulo, legenda, texto, midia, midia_url, midia_sd, midia_poster,
                    variacoes, termo, pais)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (user_id, ad_archive_id) DO UPDATE SET
                    is_active=EXCLUDED.is_active, end_date=EXCLUDED.end_date,
                    dias_ativo=EXCLUDED.dias_ativo, variacoes=EXCLUDED.variacoes,
                    midia_url=COALESCE(NULLIF(EXCLUDED.midia_url, ''), anuncios.midia_url),
                    midia_sd=COALESCE(NULLIF(EXCLUDED.midia_sd, ''), anuncios.midia_sd),
                    midia_poster=COALESCE(NULLIF(EXCLUDED.midia_poster, ''), anuncios.midia_poster),
                    atualizado_em=NOW()
            """, linhas)

        # Envio passivo (a página manda o que carregou, aos poucos) guarda o
        # termo nos anúncios mas não é uma pesquisa nova nem gasta uso.
        if termo and not dados.get("passivo"):
            conn.execute(
                "INSERT INTO pesquisas (user_id, termo, pais, min_anuncios, min_dias,"
                " total_coletado) VALUES (%s,%s,%s,%s,%s,%s)",
                (g.user["id"], termo, pais, int(dados.get("min_anuncios") or 0),
                 int(dados.get("min_dias") or 0), len(ads)))
            conn.execute(
                "UPDATE usuarios SET usos_restantes = GREATEST(0, usos_restantes - 1)"
                " WHERE id = %s AND plano <> 'admin'", (g.user["id"],))

        # destino já analisado e reprovado: sai agora, sem esperar o lote
        lowticket.podar(conn, list(urls))

        restantes = conn.execute("SELECT usos_restantes FROM usuarios WHERE id = %s",
                                 (g.user["id"],)).fetchone()["usos_restantes"]
    conn.close()

    novos_destinos = enrich.registrar(urls)
    midias.registrar([a for a in ads[:2000] if isinstance(a, dict)
                      and lowticket.link_pode_ser_low(a.get("link_url"))])
    # Copia as capas agora, enquanto a URL da Meta está fresca. O que não
    # couber no prazo fica na fila que a extensão continua moendo.
    capas = midias.processar_ate(20) if ads else {"guardadas": 0}
    return jsonify({
        "capas_guardadas": capas["guardadas"],
        "recebidos": len(ads),
        "descartados_nao_low": descartados,
        "novos": len([i for i in ids if i not in ja_tinha]),
        "destinos_na_fila": novos_destinos,
        "pendentes": enrich.pendentes(),
        "midias_pendentes": midias.pendentes(),
        "usos_restantes": restantes,
    })


@app.post("/api/anunciantes")
@precisa_token
def api_anunciantes():
    """Contagem real de anúncios ativos por anunciante (varredura profunda)."""
    dados = request.get_json(silent=True) or {}
    itens = [i for i in (dados.get("anunciantes") or [])[:500] if i.get("page_id")]
    if itens:
        conn = get_db()
        with conn:
            conn.cursor().executemany("""
                INSERT INTO anunciantes (page_id, page_name, total_ativos, escaneado_em)
                VALUES (%s,%s,%s,NOW())
                ON CONFLICT (page_id) DO UPDATE SET
                    page_name=EXCLUDED.page_name, total_ativos=EXCLUDED.total_ativos,
                    escaneado_em=NOW()
            """, [(str(i["page_id"]), (i.get("page_name") or "")[:250],
                   int(i.get("total_ativos") or 0)) for i in itens])
        conn.close()
    return jsonify({"ok": True, "atualizados": len(itens)})


@app.post("/api/enriquecer")
@precisa_token
def api_enriquecer():
    """Processa um lote de destinos. O cliente repete até `pendentes` zerar."""
    limite = max(1, min(int(request.args.get("limite", 8)), 20))
    return jsonify(enrich.processar_lote(limite))


@app.post("/api/favoritos")
@precisa_token
def api_favoritar():
    """A ★ da barra na Biblioteca cai aqui depois de ingerir o anúncio. Sem
    isso o anúncio salvo sozinho ficava invisível: um anúncio dá 1 ativo, e o
    filtro padrão do painel pede 2."""
    page_id = str((request.get_json(silent=True) or {}).get("page_id") or "")
    if not page_id:
        return jsonify({"erro": "page_id obrigatorio"}), 400
    oferta = next((o for o in montar_ofertas(g.user["id"], {})
                   if str(o["page_id"]) == page_id), None)
    if not oferta:
        return jsonify({"erro": "anunciante nao encontrado"}), 404
    conn = get_db()
    with conn:
        conn.execute("""
            INSERT INTO favoritos (user_id, page_id, page_name, dados)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id, page_id) DO UPDATE SET
                page_name = EXCLUDED.page_name, dados = EXCLUDED.dados
        """, (g.user["id"], page_id, oferta["page_name"], Json(oferta)))
        conn.execute("DELETE FROM favoritos WHERE user_id = %s AND page_id LIKE 'rec:%%'"
                     " AND page_name = %s", (g.user["id"], oferta["page_name"]))
    conn.close()
    return jsonify({"ok": True, "page_id": page_id, "page_name": oferta["page_name"]})


@app.get("/api/sem-foto")
@precisa_token
def api_sem_foto():
    """Anunciantes cuja capa não está guardada no banco — a extensão visita a
    página de cada um na Biblioteca e reenvia os anúncios com URL fresca, e a
    capa (quadro do vídeo inclusive) é copiada na hora. Aceita os filtros do
    painel (low=1 etc.) para recuperar primeiro o que você está vendo."""
    filtros = request.args.to_dict()
    limite = max(1, min(int(filtros.pop("limite", 30) or 30), 100))
    ofertas = montar_ofertas(g.user["id"], filtros)
    faltam = [o for o in ofertas
              if o["page_id"] and not str(o["imagem"] or "").startswith("/capa/")]
    return jsonify({"total": len(faltam), "anunciantes": [
        {"page_id": o["page_id"], "page_name": o["page_name"],
         "pais": (o["paises"] or ["BR"])[0]} for o in faltam[:limite]]})


@app.get("/api/auto/termos")
@precisa_token
def api_auto_termos():
    """Fila de palavras-chave da mineração automática da extensão."""
    return jsonify(autotermos.montar(g.user["id"], request.args.get("idioma", "pt")))


@app.get("/api/resumo")
@precisa_token
def api_resumo():
    """Quantos anunciantes low ticket o minerador tem agora."""
    return jsonify({"low_ticket": len(montar_ofertas(g.user["id"], {}))})


@app.post("/api/ideias")
@precisa_token
def api_ideias():
    """Ideia livre ("produtos para o natal") -> palavras-chave para a fila."""
    dados = request.get_json(silent=True) or {}
    return jsonify(ideias.gerar(str(dados.get("ideia", "")), str(dados.get("idioma", "pt"))))


@app.post("/api/midias")
@precisa_token
def api_midias():
    """Copia um lote de mídias da CDN da Meta para o Blob."""
    return jsonify(midias.processar_lote(int(request.args.get("limite", 3))))


# ---------------------------------------------------------------- consulta

def montar_ofertas(user_id: int, filtros, com_total: bool = False):
    conn = get_db()
    # Colunas na mão, não `a.*`: o painel recarrega sozinho e cada leitura
    # trazia `texto` inteiro (1500 caracteres por anúncio) e campos que ninguém
    # usa. Isso é tráfego do banco, e tráfego é cota.
    linhas = conn.execute("""
        SELECT a.ad_archive_id, a.page_id, a.page_name, a.is_active, a.start_date,
               a.dias_ativo, a.plataformas, a.cta_text, a.link_url, a.midia,
               a.midia_url, a.midia_poster, a.variacoes, a.termo, a.pais,
               a.titulo, a.legenda,
               LEFT(a.texto, 400) AS texto,
               d.url_final, d.dominio, d.gateway,
               d.checkout_url, d.preco, d.preco_valor, d.preco_moeda,
               d.imagem, d.status AS destino_status,
               m.video_url, m.poster_url,
               an.total_ativos AS total_ativos_real
        FROM anuncios a
        LEFT JOIN destinos d ON d.url = a.link_url
        LEFT JOIN midias m ON m.ad_archive_id = a.ad_archive_id
        LEFT JOIN anunciantes an ON an.page_id = a.page_id
        WHERE a.user_id = %s AND a.excluido_em IS NULL
    """, (user_id,)).fetchall()
    conn.close()

    grupos: dict[str, dict] = {}
    for r in linhas:
        chave = r["page_id"] or r["page_name"] or r["ad_archive_id"]
        item = grupos.setdefault(chave, {
            "page_id": r["page_id"], "page_name": r["page_name"],
            "anuncios_coletados": 0, "variacoes": 0, "ativos": 0,
            "total_ativos_real": r["total_ativos_real"],
            "dias_rodando": 0, "dias_novo": None, "primeiro_anuncio": None,
            "termos": set(), "paises": set(), "plataformas": set(), "midias": set(),
            "dominios": {}, "gateways": {}, "destinos": {}, "precos": [],
            "ofertas": {},
            "checkout_url": "", "melhor_texto": "", "cta": set(),
            "imagem": "", "imagem_anuncio": "", "video": "", "poster": "",
            "pendente_enriquecimento": False,
        })
        item["anuncios_coletados"] += 1
        item["variacoes"] += r["variacoes"] or 1
        item["ativos"] += 1 if r["is_active"] else 0
        item["dias_rodando"] = max(item["dias_rodando"], r["dias_ativo"] or 0)
        # o mais novo diz se o anunciante ainda está subindo criativo
        if r["dias_ativo"] is not None:
            item["dias_novo"] = (r["dias_ativo"] if item["dias_novo"] is None
                                 else min(item["dias_novo"], r["dias_ativo"]))
        if r["start_date"] and (item["primeiro_anuncio"] is None
                                or r["start_date"] < item["primeiro_anuncio"]):
            item["primeiro_anuncio"] = r["start_date"]
        if r["termo"]:
            item["termos"].add(r["termo"])
        if r["pais"]:
            item["paises"].add(r["pais"])
        for p in (r["plataformas"] or "").split(","):
            if p:
                item["plataformas"].add(p)
        if r["midia"]:
            item["midias"].add(r["midia"])
        if r["cta_text"]:
            item["cta"].add(r["cta_text"])
        if r["dominio"]:
            item["dominios"][r["dominio"]] = item["dominios"].get(r["dominio"], 0) + 1
        if r["gateway"]:
            item["gateways"][r["gateway"]] = item["gateways"].get(r["gateway"], 0) + 1
        if r["url_final"]:
            item["destinos"][r["url_final"]] = item["destinos"].get(r["url_final"], 0) + 1
        if r["checkout_url"] and not item["checkout_url"]:
            item["checkout_url"] = r["checkout_url"]
        if r["imagem"] and not item["imagem"]:
            item["imagem"] = r["imagem"]
        # Reserva: a URL crua da CDN da Meta. Ela expira, mas quem carrega é o
        # navegador do usuário (IP e sessão dele), então funciona enquanto vale —
        # e é o que salva a capa quando a cópia no Blob falha.
        if not item["imagem_anuncio"]:
            item["imagem_anuncio"] = meta_viva(r["midia_poster"]) or (
                meta_viva(r["midia_url"]) if (r["midia"] or "").startswith("imagem") else "")
        # o anúncio com mais variações costuma ser o criativo principal
        if midia_viva(r["video_url"]) and not item["video"]:
            item["video"] = midia_viva(r["video_url"])
        if midia_viva(r["poster_url"]) and not item["poster"]:
            item["poster"] = midia_viva(r["poster_url"])
        if r["preco"]:
            # (valor, texto): ordenar por string põe "R$ 100" antes de "R$ 9,90"
            item["precos"].append((float(r["preco_valor"] or 0), r["preco"],
                                   r["preco_moeda"] or ""))
        if r["link_url"] and r["destino_status"] in (None, "pendente", "processando"):
            item["pendente_enriquecimento"] = True
        dominio_oferta = lowticket.dominio_da_oferta(r["link_url"], r["dominio"])
        oferta = item["ofertas"].setdefault(dominio_oferta, {
            "ativos": 0, "criativos": 0, "dias": 0, "copies": []
        })
        oferta["ativos"] += 1 if r["is_active"] else 0
        oferta["criativos"] += r["variacoes"] or 1
        oferta["dias"] = max(oferta["dias"], r["dias_ativo"] or 0)
        copy = " ".join(filter(None, (r["texto"], r["titulo"], r["legenda"], r["cta_text"])))
        oferta["copies"].append((r["termo"] or "", copy))
        # Anúncio de catálogo traz o molde cru ("{{product.brand}}") no lugar
        # da copy: não serve para ler a oferta, fica com o de outro anúncio.
        texto = r["texto"] or ""
        if "{{" not in texto and len(texto) > len(item["melhor_texto"]):
            item["melhor_texto"] = texto

    maior = lambda d: (max(d.items(), key=lambda x: x[1])[0] if d else "")  # noqa: E731

    saida = []
    for it in grupos.values():
        total_ativos = it["total_ativos_real"] or it["ativos"] or it["anuncios_coletados"]
        # menor preço = oferta de entrada, que é o que interessa em low ticket
        barato = min((p for p in it["precos"] if p[0] > 0), default=None)
        o = {
            "page_id": it["page_id"],
            "page_name": it["page_name"],
            "anuncios_ativos": total_ativos,
            "contagem_real": bool(it["total_ativos_real"]),
            "anuncios_coletados": it["anuncios_coletados"],
            "variacoes": it["variacoes"],
            "dias_rodando": it["dias_rodando"],
            "dias_novo": it["dias_novo"] if it["dias_novo"] is not None else 0,
            "primeiro_anuncio": (
                datetime.fromtimestamp(it["primeiro_anuncio"], tz=timezone.utc)
                .strftime("%Y-%m-%d") if it["primeiro_anuncio"] else ""),
            "dominio": maior(it["dominios"]),
            "destino": maior(it["destinos"]),
            # anúncio que leva direto ao checkout não tem LP para mostrar
            "sem_lp": e_gateway(maior(it["destinos"])),
            "gateway": maior(it["gateways"]),
            "checkout_url": it["checkout_url"],
            # og:image do destino é a foto do produto; a mídia do anúncio é
            # reserva (URL assinada da CDN da Meta, que expira em algumas horas).
            # O criativo do anúncio vem primeiro: é o que está rodando e é o que
            # você quer bater o olho. O og:image do destino entra quando não há
            # criativo — muita loja usa og:image genérico (logo, imagem padrão
            # da plataforma), que como capa não diz nada.
            "imagem": it["poster"] or it["imagem_anuncio"] or it["imagem"],
            # guardado à parte para o retrato de Melhores sobreviver ao Blob
            # As três fontes vão juntas: a capa escolhida pode morrer no ar (URL
            # da CDN da Meta expira) e o painel troca pela seguinte sem recarregar.
            "imagem_anuncio": it["imagem_anuncio"],
            "imagem_site": it["imagem"],
            "imagem_do_site": not (it["poster"] or it["imagem_anuncio"]) and bool(it["imagem"]),
            "imagem_e_reserva": not it["poster"] and bool(it["imagem_anuncio"]),
            "video": it["video"],
            "poster": it["poster"],
            "preco": barato[1] if barato else "",
            "preco_valor": barato[0] if barato else 0,
            "moeda": barato[2] if barato else "",
            "preco_brl": round(barato[0] * COTACAO_BRL.get(barato[2], 0), 2) if barato else 0,
            "tipo_gateway": tipo_de(maior(it["gateways"])),
            "destino_venda": bool(maior(it["dominios"])
                                  and maior(it["dominios"]) not in NAO_VENDE),
            "termos": sorted(it["termos"]),
            "paises": sorted(it["paises"]),
            "plataformas": sorted(it["plataformas"]),
            "cta": sorted(it["cta"])[:3],
            "copy": it["melhor_texto"][:400],
            "copy_qualificada": [],
            "criterios_low_ticket": [],
            "oferta_dominio": "",
            "criativos_oferta": 0,
            "pendente": it["pendente_enriquecimento"],
            "url_biblioteca": (
                "https://www.facebook.com/ads/library/?active_status=active"
                f"&ad_type=all&country=BR&view_all_page_id={it['page_id']}"
                "&search_type=page&media_type=all" if it["page_id"] else ""),
        }
        # Escala = anúncios ativos ponderados pelo tempo que a oferta aguenta rodar.
        o["score"] = round(o["anuncios_ativos"] * (1 + o["dias_rodando"] / 30), 1)
        # Qualificação nova: palavra-chave/derivado na copy, pelo menos um
        # gatilho low ticket, mais de 15 dias e 5+ anúncios/criativos da mesma
        # oferta (mesmo anunciante + domínio), não de produtos misturados.
        for dominio, oferta in it["ofertas"].items():
            volume = max(oferta["ativos"], oferta["criativos"])
            if oferta["dias"] <= LOW_TICKET_DIAS_MIN or volume < LOW_TICKET_CRIATIVOS_MIN:
                continue
            for termo_copy, copy in oferta["copies"]:
                q = lowticket.qualifica_copy(termo_copy, copy)
                if q["qualifica_copy"]:
                    o["copy_qualificada"].append(termo_copy or "")
                    o["criterios_low_ticket"].extend(
                        c["categoria"] for c in q["criterios_low_ticket"]
                    )
                    o["oferta_dominio"] = dominio
                    o["criativos_oferta"] = volume
                    break
            if o["oferta_dominio"]:
                break
        o["copy_qualificada"] = sorted(set(x for x in o["copy_qualificada"] if x))
        o["criterios_low_ticket"] = sorted(set(o["criterios_low_ticket"]))
        o["qualificado_low_ticket"] = bool(o["oferta_dominio"])
        saida.append(o)

    min_ads = int(filtros.get("min_anuncios") or 0)
    min_dias = int(filtros.get("min_dias") or 0)
    gateway = (filtros.get("gateway") or "").lower()
    termo = (filtros.get("termo") or "").lower()
    pais = (filtros.get("pais") or "").upper()
    busca = (filtros.get("q") or "").lower()
    tipo = (filtros.get("tipo") or "").lower()
    so_venda = filtros.get("so_venda") in ("1", "true", "on")
    com_preco = filtros.get("com_preco") in ("1", "true", "on")
    com_foto = filtros.get("com_foto") in ("1", "true", "on")
    # Low ticket = preço detectado até R$ 50 (ou o "até" da tela), com página
    # de checkout e destino que vende — perfil, app e WhatsApp ficam de fora.
    # O produto agora tem um único modo: pesquisa Low Ticket qualificada.
    low = True

    def numero(chave):
        try:
            return float(filtros.get(chave) or 0)
        except (TypeError, ValueError):
            return 0.0

    preco_min, preco_max = numero("preco_min"), numero("preco_max")
    if low:
        com_preco = so_venda = True
        preco_max = preco_max or LOW_TICKET_MAX

    def passa(i: dict) -> bool:
        if not i["qualificado_low_ticket"]:
            return False
        if i["anuncios_ativos"] < min_ads or i["dias_rodando"] < min_dias:
            return False
        if gateway and gateway not in (i["gateway"] or "").lower():
            return False
        if pais and pais not in i["paises"]:
            return False
        # "plataforma" = onde a venda acontece de fato (infoproduto ou loja),
        # em oposição a só ter selo de meio de pagamento na página
        if tipo == "plataforma":
            if i["tipo_gateway"] not in ("infoproduto", "ecommerce"):
                return False
        elif tipo and i["tipo_gateway"] != tipo:
            return False
        if so_venda and not i["destino_venda"]:
            return False
        if (com_preco or preco_min or preco_max) and not i["preco_brl"]:
            return False
        if preco_min and i["preco_brl"] < preco_min:
            return False
        if preco_max and i["preco_brl"] > preco_max:
            return False
        if low and not (i["checkout_url"]
                        or i["tipo_gateway"] in ("infoproduto", "ecommerce")):
            return False
        if com_foto and not (i["imagem"] or i["video"] or i["imagem_site"]):
            return False
        if termo and termo not in " ".join(i["termos"]).lower() and termo not in i["copy"].lower():
            # O termo digitado deve ser o termo da pesquisa ou aparecer na copy;
            # a qualificação da copy já foi feita por anúncio acima.
            return False
        if busca and busca not in " ".join(str(v) for v in i.values()).lower():
            return False
        return True

    total = len(saida)
    saida = [i for i in saida if passa(i)]
    saida.sort(key=lambda i: (-i["score"], -i["anuncios_ativos"]))
    # o total sem filtro é o que deixa o painel avisar "22 de 56": filtro que
    # esconde em silêncio parece dado faltando
    return (saida, total) if com_total else saida


def _anuncios_do_page(user_id: int, page_id: str) -> list[dict]:
    conn = get_db()
    rows = conn.execute("""
        SELECT a.*, d.url_final, d.gateway, d.checkout_url, d.preco, d.dominio
        FROM anuncios a LEFT JOIN destinos d ON d.url = a.link_url
        WHERE a.user_id = %s AND a.page_id = %s AND a.excluido_em IS NULL
        ORDER BY a.start_date DESC NULLS LAST
    """, (user_id, page_id)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/ofertas")
@precisa_token
def api_ofertas():
    return jsonify({"ofertas": montar_ofertas(g.user["id"], request.args)})


@app.get("/api/anunciante/<page_id>")
@precisa_token
def api_anunciante(page_id):
    return jsonify({"anuncios": _anuncios_do_page(g.user["id"], page_id)})


# ---------------------------------------------------------------- painel web

@app.get("/login")
def login_page():
    return render_template("login.html", erro=request.args.get("erro"))


@app.post("/login")
def login_post():
    conn = get_db()
    row = conn.execute("SELECT * FROM usuarios WHERE username = %s",
                       (request.form.get("username", "").strip(),)).fetchone()
    conn.close()
    if not row or not confere_senha(request.form.get("password", ""), row["password_hash"]):
        return redirect(url_for("login_page", erro="Usuário ou senha inválidos"))
    session["uid"] = row["id"]
    session.permanent = True
    return redirect(url_for("dashboard"))


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.get("/")
@precisa_sessao
def dashboard():
    return render_template("dashboard.html", usuario=g.user["username"],
                           plano=g.user["plano"], usos=g.user["usos_restantes"])


@app.get("/dados/ofertas")
@precisa_sessao
def dados_ofertas():
    ofertas, total = montar_ofertas(g.user["id"], request.args, com_total=True)
    return jsonify({
        "ofertas": ofertas,
        "resumo": {
            "anunciantes": len(ofertas),
            "total": total,
            "anuncios": sum(o["anuncios_ativos"] for o in ofertas),
            "com_gateway": sum(1 for o in ofertas if o["gateway"]),
            "destinos_pendentes": enrich.pendentes(),
            "midias_pendentes": midias.pendentes(),
        },
    })


@app.get("/dados/anunciante/<page_id>")
@precisa_sessao
def dados_anunciante(page_id):
    return jsonify({"anuncios": _anuncios_do_page(g.user["id"], page_id)})


@app.post("/dados/enriquecer")
@precisa_sessao
def dados_enriquecer():
    return jsonify(enrich.processar_lote(int(request.args.get("limite", 8))))


@app.post("/dados/midias")
@precisa_sessao
def dados_midias():
    return jsonify(midias.processar_lote(int(request.args.get("limite", 3))))


@app.post("/dados/reprocessar")
@precisa_sessao
def dados_reprocessar():
    novas = midias.registrar_do_banco()   # anúncios antigos, de antes da cópia de mídia
    return jsonify({"enfileirados": enrich.reenfileirar() + midias.reenfileirar() + novas,
                    "pendentes": enrich.pendentes(),
                    "midias_pendentes": midias.pendentes()})


# ---------------------------------------------------------------- melhores / limpeza

MIDIA = ("imagem", "video", "poster", "imagem_do_site", "imagem_e_reserva")


@app.get("/dados/favoritos")
@precisa_sessao
def dados_favoritos():
    """O retrato guarda as métricas do dia em que você salvou — é o ponto de
    Melhores. Já a capa não: ela é buscada de novo a cada leitura, senão um
    favorito salvo antes de a mídia ser copiada fica sem foto para sempre."""
    conn = get_db()
    linhas = conn.execute(
        "SELECT page_id, dados, nota, criado_em FROM favoritos WHERE user_id = %s"
        " ORDER BY criado_em DESC", (g.user["id"],)).fetchall()
    conn.close()

    # Antes isto refazia `montar_ofertas` (lê todos os anúncios) a cada abertura
    # do painel — o dobro de tráfego só para achar capa. Agora é uma consulta
    # enxuta pelos page_id que interessam.
    ids = [str(r["page_id"]) for r in linhas]
    conn = get_db()
    midias_por_page = {}
    for r in conn.execute("""
        SELECT a.page_id,
               MAX(NULLIF(m.video_url, '')) AS video,
               MAX(NULLIF(m.poster_url, '')) AS poster,
               MAX(NULLIF(d.imagem, '')) AS imagem,
               MAX(NULLIF(a.midia_poster, '')) AS imagem_anuncio
        FROM anuncios a
        LEFT JOIN midias m ON m.ad_archive_id = a.ad_archive_id
        LEFT JOIN destinos d ON d.url = a.link_url
        WHERE a.user_id = %s AND a.excluido_em IS NULL AND a.page_id = ANY(%s)
        GROUP BY a.page_id
    """, (g.user["id"], ids)).fetchall():
        midias_por_page[str(r["page_id"])] = r
    conn.close()

    atuais = {}
    for pid, r in midias_por_page.items():
        poster = midia_viva(r["poster"])
        r = {**r, "imagem_anuncio": meta_viva(r["imagem_anuncio"])}
        atuais[pid] = {
            "imagem": poster or r["imagem_anuncio"] or r["imagem"] or "",
            "video": midia_viva(r["video"]),
            "poster": poster,
            "imagem_do_site": not (r["imagem_anuncio"] or poster) and bool(r["imagem"]),
            "imagem_e_reserva": bool(r["imagem_anuncio"]) and not poster,
        }
    saida, orfaos = [], []
    for r in linhas:
        dados = dict(r["dados"])
        # retrato antigo pode apontar para o Blob; se ele está fora, não serve
        if not BLOB_ATIVO:
            for k in ("imagem", "video", "poster"):
                if "blob.vercel-storage" in (dados.get(k) or ""):
                    dados[k] = ""
        agora = atuais.get(str(r["page_id"]))
        if agora and (agora.get("imagem") or agora.get("video")):
            dados.update({k: agora.get(k) for k in MIDIA})
        if not (dados.get("imagem") or dados.get("video")):
            dados["imagem"] = dados.get("imagem_anuncio") or ""
            if not dados["imagem"] and dados.get("destino"):
                orfaos.append(dados)
        saida.append({**dados, "nota": r["nota"],
                      "salvo_em": r["criado_em"].strftime("%Y-%m-%d")})

    # Favorito cujo anúncio já foi limpo do banco: a tabela `destinos` continua
    # lá e guarda o og:image daquela página — é a última chance de ter capa.
    if orfaos:
        conn = get_db()
        achados = {r["url_final"]: r["imagem"] for r in conn.execute(
            "SELECT url_final, imagem FROM destinos WHERE url_final = ANY(%s) AND imagem <> ''",
            ([d["destino"] for d in orfaos],)).fetchall()}
        conn.close()
        for d in orfaos:
            if achados.get(d["destino"]):
                d["imagem"] = achados[d["destino"]]
                d["imagem_do_site"] = True
    return jsonify({"favoritos": saida})


@app.post("/dados/favoritos")
@precisa_sessao
def dados_favoritar():
    """Salva o retrato atual da oferta em 'melhores'. Sem filtro na busca: o
    anunciante precisa ser achado mesmo que os filtros da tela o escondam."""
    dados = request.get_json(silent=True) or {}
    ids = _page_ids(dados)
    if not ids:
        return jsonify({"erro": "page_id ou page_ids obrigatorio"}), 400

    # `dados.retrato` chega no desfazer: a oferta pode nem existir mais nos
    # resultados, e o que importa é devolver o retrato que estava salvo.
    retrato = dados.get("retrato")
    if retrato:
        ofertas = [retrato]
    else:
        todas = {str(o["page_id"]): o for o in montar_ofertas(g.user["id"], {})}
        ofertas = [todas[i] for i in ids if i in todas]
        if not ofertas:
            return jsonify({"erro": "anunciante nao encontrado nos resultados"}), 404

    conn = get_db()
    with conn:
        conn.cursor().executemany("""
            INSERT INTO favoritos (user_id, page_id, page_name, dados)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (user_id, page_id) DO UPDATE SET
                page_name = EXCLUDED.page_name, dados = EXCLUDED.dados
        """, [(g.user["id"], str(o["page_id"]), o["page_name"], Json(o)) for o in ofertas])
        # O mesmo anunciante salvo de verdade aposenta a versão recuperada
        # (page_id sintético `rec:`), senão ficariam dois cartões iguais.
        conn.execute("""
            DELETE FROM favoritos
            WHERE user_id = %s AND page_id LIKE 'rec:%%' AND page_name = ANY(%s)
        """, (g.user["id"], [o["page_name"] for o in ofertas]))
    conn.close()
    return jsonify({"ok": True, "salvos": len(ofertas)})


@app.post("/dados/favoritos/remover")
@precisa_sessao
def dados_desfavoritar():
    ids = _page_ids(request.get_json(silent=True) or {})
    conn = get_db()
    with conn:
        r = conn.execute("DELETE FROM favoritos WHERE user_id = %s AND page_id = ANY(%s)",
                         (g.user["id"], ids))
    conn.close()
    return jsonify({"ok": True, "removidos": r.rowcount})


def _page_ids(dados) -> list[str]:
    ids = dados.get("page_ids") or ([dados["page_id"]] if dados.get("page_id") else [])
    return [str(i) for i in ids if str(i).strip()]


@app.post("/dados/excluir")
@precisa_sessao
def dados_excluir():
    """Esconde um ou vários anunciantes dos resultados. Some da tela na hora e
    dá para desfazer — por isso marca `excluido_em` em vez de apagar. Não mexe
    em 'melhores': se estava salvo lá, o retrato continua."""
    dados = request.get_json(silent=True) or {}
    ids = _page_ids(dados)
    if not ids:
        return jsonify({"erro": "page_id ou page_ids obrigatorio"}), 400
    conn = get_db()
    with conn:
        n = conn.execute(
            "UPDATE anuncios SET excluido_em = NOW()"
            " WHERE user_id = %s AND page_id = ANY(%s) AND excluido_em IS NULL",
            (g.user["id"], ids)).rowcount
    conn.close()
    return jsonify({"ok": True, "anuncios": n, "anunciantes": len(ids), "page_ids": ids})


@app.post("/dados/restaurar")
@precisa_sessao
def dados_restaurar():
    """Desfazer da exclusão."""
    ids = _page_ids(request.get_json(silent=True) or {})
    conn = get_db()
    with conn:
        n = conn.execute("UPDATE anuncios SET excluido_em = NULL"
                         " WHERE user_id = %s AND page_id = ANY(%s)",
                         (g.user["id"], ids)).rowcount
    conn.close()
    return jsonify({"ok": True, "anuncios": n})


@app.post("/dados/limpar")
@precisa_sessao
def dados_limpar():
    """Arquiva resultados sem apagar os anúncios nem o histórico de pesquisas.
    Mantido para clientes antigos; /dados/restaurar desfaz pelo page_id."""
    conn = get_db()
    with conn:
        anuncios = conn.execute(
            "UPDATE anuncios SET excluido_em = NOW()"
            " WHERE user_id = %s AND excluido_em IS NULL",
            (g.user["id"],)).rowcount
    conn.close()
    return jsonify({"ok": True, "anuncios": anuncios, "pesquisas": 0,
                    "reversivel": True})


@app.get("/api/token-sessao")
@precisa_sessao
def token_sessao():
    """Gera um token para colar na extensão sem digitar a senha de novo."""
    return jsonify({"token": novo_token(g.user["id"])})


@app.get("/capa/<ad_id>")
def capa(ad_id):
    """Miniatura guardada no banco. Sem login: é <img> de página já autenticada,
    e o conteúdo é o criativo público da Biblioteca de Anúncios.
    Cache imutável — a capa de um anúncio nunca muda, e sem isso cada abertura
    do painel repuxaria tudo do Postgres (foi cota de transferência que já
    derrubou a aplicação uma vez)."""
    conn = get_db()
    row = conn.execute("SELECT jpeg, mime FROM capas WHERE ad_archive_id = %s",
                       (str(ad_id)[:40],)).fetchone()
    conn.close()
    if not row:
        return ("", 404)
    return app.response_class(bytes(row["jpeg"]), mimetype=row["mime"] or "image/jpeg",
                              headers={
        "Cache-Control": "public, max-age=31536000, immutable",
    })


@app.get("/api/saude")
def saude():
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return jsonify({"ok": True, "banco": "conectado"})
    except Exception as e:
        return jsonify({"ok": False, "erro": str(e)[:200]}), 500


if __name__ == "__main__":
    porta = int(os.getenv("MINERADOR_PORTA", "5010"))
    print(f"minerador em http://127.0.0.1:{porta}")
    app.run(host="0.0.0.0", port=porta, debug=False, threaded=True)
