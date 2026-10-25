/**
 * Análise do DMARC.
 *
 * O DMARC é o registro que diz o que fazer com quem falsifica o seu domínio. Sem
 * ele, quem recebe decide sozinho, e a decisão costuma ser jogar no spam.
 */
import type { LeitorDns } from "./spf.js";

export interface AnaliseDmarc {
  registros: string[];
  existe: boolean;
  bruto: string | null;
  politica: string | null;
  politicaSubdominio: string | null;
  pct: number | null;
  rua: string[];
  ruf: string[];
  aspf: string | null;
  adkim: string | null;
  erros: string[];
  avisos: string[];
}

const SEPARAR = (texto: string): Map<string, string> => {
  const mapa = new Map<string, string>();
  for (const pedaco of texto.split(";")) {
    const [chave, ...resto] = pedaco.split("=");
    if (!chave) continue;
    mapa.set(chave.trim().toLowerCase(), resto.join("=").trim());
  }
  return mapa;
};

export async function analisarDmarc(dominio: string, leitor: LeitorDns): Promise<AnaliseDmarc> {
  const registros = (await leitor.txt(`_dmarc.${dominio}`)).map((r) => r.trim());
  const candidatos = registros.filter((r) => /v=dmarc1/i.test(r));

  const vazio: AnaliseDmarc = {
    registros,
    existe: false,
    bruto: null,
    politica: null,
    politicaSubdominio: null,
    pct: null,
    rua: [],
    ruf: [],
    aspf: null,
    adkim: null,
    erros: [],
    avisos: [],
  };

  if (candidatos.length === 0) return vazio;

  const erros: string[] = [];
  const avisos: string[] = [];

  if (candidatos.length > 1) {
    erros.push(`${dominio} publica mais de um DMARC, e os sistemas usam apenas o primeiro`);
  }

  const bruto = candidatos[0] ?? "";
  const tags = SEPARAR(bruto);

  const politica = (tags.get("p") ?? "").toLowerCase() || null;
  const politicaSubdominio = (tags.get("sp") ?? "").toLowerCase() || null;
  const pctTexto = tags.get("pct");
  const pct = pctTexto ? Number(pctTexto) : null;

  if (!politica) {
    erros.push("o DMARC não informa a política p, então o registro é inválido e acaba ignorado");
  } else if (!["none", "quarantine", "reject"].includes(politica)) {
    erros.push(`a política p=${politica} não existe: só valem none, quarantine e reject`);
  }

  if (pct !== null && (!Number.isInteger(pct) || pct < 0 || pct > 100)) {
    erros.push(`pct=${pctTexto} está fora da faixa de 0 a 100`);
  }

  const rua = (tags.get("rua") ?? "")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);
  const ruf = (tags.get("ruf") ?? "")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);

  for (const endereco of rua) {
    if (!/^mailto:[^@\s]+@[^@\s]+$/i.test(endereco)) {
      erros.push(`o endereço de relatório "${endereco}" não está no formato mailto:algo@dominio`);
    }
  }

  return {
    registros,
    existe: true,
    bruto,
    politica,
    politicaSubdominio,
    pct,
    rua,
    ruf,
    aspf: tags.get("aspf") ?? null,
    adkim: tags.get("adkim") ?? null,
    erros,
    avisos,
  };
}
