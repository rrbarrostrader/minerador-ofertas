"""Regra única de low ticket: o minerador só guarda oferta de entrada.

Preço e checkout só se sabem depois de visitar o destino (enrich.py), então o
corte acontece em dois momentos:

- na ingestão, sai na hora o que nunca vai ser low ticket (sem link, app,
  perfil, WhatsApp) e o que tem destino já analisado e reprovado;
- depois de cada lote de enriquecimento, sai o que acabou de ser reprovado.

"Sair" é `excluido_em` — o mesmo ✕ reversível do painel. Melhores não é tocado.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

from gateways import IGNORAR, host, tipo_de

# Low ticket se mede em real: US$ 49 não é oferta de entrada no Brasil.
# Cotação fixa e redonda de propósito — o corte é grosso, não contábil.
COTACAO_BRL = {"": 1.0, "BRL": 1.0, "USD": 5.5, "EUR": 6.0}
LOW_TICKET_MAX = 50.0

# Destino que não é página de venda: perfil, conversa, loja de app.
NAO_VENDE = IGNORAR | {"apps.apple.com", "play.google.com", "fb.me", "linktr.ee",
                       "beacons.ai", "bio.link", "linkr.bio", "itunes.apple.com",
                       "m.me", "web.whatsapp.com"}

# Encurtador e redirecionador levam a página de venda: só dá para julgar depois
# de seguir o link, então não podem cair no corte de entrada.
REDIRECIONA = {"bit.ly", "t.co", "l.facebook.com", "lm.facebook.com"}

MAX_TENTATIVAS = 3   # mesmo teto do enrich: destino que esgotou não volta


def link_pode_ser_low(link: str) -> bool:
    """Antes de visitar o site: só descarta o que com certeza não vende."""
    link = (link or "").strip()
    h = host(link)
    return link.startswith("http") and (h in REDIRECIONA or h not in NAO_VENDE)


def preco_brl(valor, moeda: str) -> float:
    return float(valor or 0) * COTACAO_BRL.get(moeda or "", 0)


def destino_e_low(d: dict) -> bool:
    """Destino já analisado: até R$ 50, com checkout, num site que vende."""
    if host(d.get("url_final") or d.get("url") or "") in NAO_VENDE:
        return False
    if not 0 < preco_brl(d.get("preco_valor"), d.get("preco_moeda")) <= LOW_TICKET_MAX:
        return False
    return bool(d.get("checkout_url")) or tipo_de(d.get("gateway") or "") in ("infoproduto",
                                                                          "ecommerce")


def podar(conn, urls=None) -> int:
    """Esconde os anúncios cujo destino já foi decidido e não é low ticket.
    `urls=None` passa o pente no banco inteiro."""
    filtro, args = "", [MAX_TENTATIVAS]
    if urls is not None:
        urls = [u for u in urls if u]
        if not urls:
            return 0
        filtro, args = " AND url = ANY(%s)", [MAX_TENTATIVAS, urls]
    # Decidido = analisado com sucesso, ou esgotou as tentativas (site fora do
    # ar não dá para provar preço nem checkout).
    linhas = conn.execute(f"""
        SELECT url, url_final, preco_valor, preco_moeda, checkout_url, gateway
        FROM destinos
        WHERE (status = 'ok' OR (status = 'erro' AND tentativas >= %s)){filtro}
    """, args).fetchall()
    reprovados = [r["url"] for r in linhas if not destino_e_low(dict(r))]

    n = 0
    if reprovados:
        n += conn.execute("""
            UPDATE anuncios SET excluido_em = NOW()
            WHERE excluido_em IS NULL AND link_url = ANY(%s)
        """, (reprovados,)).rowcount
    if urls is None:
        # sobra de antes da regra: anúncio sem link ou com link de app/perfil
        for r in conn.execute("SELECT DISTINCT link_url FROM anuncios WHERE excluido_em IS NULL"
                              ).fetchall():
            if not link_pode_ser_low(r["link_url"]):
                n += conn.execute("""
                    UPDATE anuncios SET excluido_em = NOW()
                    WHERE excluido_em IS NULL AND link_url IS NOT DISTINCT FROM %s
                """, (r["link_url"],)).rowcount
    return n


# ---------------------------------------------------------------------------
# Qualificação da pesquisa Low Ticket: copy + palavra-chave + persistência.

LOW_TICKET_DIAS_MIN = 15
LOW_TICKET_CRIATIVOS_MIN = 5

LOW_TICKET_COPY_REGRAS = (
    ("gancho de preço", (
        r"menos de(?:\s+rs?\$?\s*[\d,.]+)?\s*(?:por\s+dia|por\s+m[eê]s|por\s+semana)?",
        r"por\s+apenas", r"apenas\s+rs?\$?", r"pre[cç]o\s+de\s+(?:banana|custo)",
        r"menos que um\s+(?:lanche|cafe|caf[eé]|pizza)", r"valor\s+simb[oó]lico",
        r"desconto\s+de\s+lan[cç]amento", r"economiz[aeiou]+",
    )),
    ("promessa de resolução", (
        r"pronto\s+para\s+usar", r"c[oó]pia\s+e\s+cola", r"passo\s+a\s+passo",
        r"m[eé]todo\s+(?:validado|simples)", r"em\s+\d+\s+minutos?",
        r"em\s+menos\s+de\s+\d+\s+hora", r"do\s+zero\s+ao\s+\w+",
        r"automatizad[oa]", r"ferramenta\s+secreta",
    )),
    ("produto empacotado", (
        r"\bpack\b", r"\bkit\b", r"combo\s+completo", r"modelo\s+edit[aá]vel",
    )),
    ("dor ou bloqueio", (
        r"trav[aá]do", r"sem\s+tempo", r"sem\s+dinheiro", r"or[cç]amento\s+apertado",
        r"n[aã]o\s+sabe\s+por\s+onde\s+come[cç]ar", r"erros\s+comuns",
        r"armadilhas", r"zero\s+resultados?", r"n[aã]o\s+vende\s+nada",
        r"trabalho\s+manual", r"perrengue", r"dificuldade\s+com",
    )),
    ("chamada para ação", (
        r"garantir\s+meu\s+acesso", r"baixar\s+agora", r"desbloquear",
        r"quero\s+o\s+kit\s+completo", r"acessar\s+(?:a\s+)?(?:ferramenta|material)",
    )),
)


def normalizar_copy(valor) -> str:
    texto = unicodedata.normalize("NFKD", str(valor or "")).encode(
        "ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", " ", texto).strip()


def _regex_normalizada(regex: str) -> str:
    texto = unicodedata.normalize("NFKD", regex).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"\s+", lambda _m: r"\s+", texto)


def sinais_lowticket(copy: str) -> list[dict]:
    texto = normalizar_copy(copy)
    achados = []
    for categoria, regras in LOW_TICKET_COPY_REGRAS:
        encontrados = []
        for regra in regras:
            if re.search(_regex_normalizada(regra), texto):
                encontrados.append(regra.replace(r"\b", "").replace("\\s+", " "))
        if encontrados:
            achados.append({"categoria": categoria, "termos": encontrados})
    return achados


def palavra_na_copy(termo: str, copy: str) -> bool:
    """Aceita a palavra-chave e flexões/derivados simples em português."""
    tokens_termo = re.findall(r"[a-z0-9]+", normalizar_copy(termo))
    tokens_copy = re.findall(r"[a-z0-9]+", normalizar_copy(copy))
    if not tokens_termo or not tokens_copy:
        return False
    for alvo in tokens_termo:
        if len(alvo) < 4:
            if alvo not in tokens_copy:
                return False
            continue
        base = alvo[:max(4, len(alvo) - 2)]
        if not any(p.startswith(base) for p in tokens_copy):
            return False
    return True


def qualifica_copy(termo: str, copy: str) -> dict:
    achados = sinais_lowticket(copy)
    palavra = palavra_na_copy(termo, copy)
    return {
        "palavra_chave_encontrada": palavra,
        "criterios_low_ticket": achados,
        "qualifica_copy": bool(achados) and palavra,
    }


def dominio_da_oferta(url: str, dominio: str = "") -> str:
    bruto = (dominio or "").strip().lower() or (urlsplit(url or "").hostname or "").lower()
    return bruto.removeprefix("www.")
