/**
 * Análise do SPF.
 *
 * O SPF é uma lista de regras separada por espaço que o servidor de destino
 * percorre até achar a primeira que casa. O trabalho aqui é ler essa lista,
 * seguir os include: até o fim e contar as consultas DNS, porque o limite de 10
 * é o defeito mais comum de tudo que existe publicado por aí.
 *
 * A função recebe o leitor de TXT por parâmetro para poder ser testada com
 * respostas fixas, sem tocar na rede.
 */
import type { ServidorMx } from "./dns.js";

export const LIMITE_CONSULTAS = 10;

export interface Mecanismo {
  bruto: string;
  qualificador: string;
  nome: string;
  valor: string | null;
}

export interface AnaliseSpf {
  registros: string[];
  mecanismos: Mecanismo[];
  qualificadorAll: string | null;
  consultas: number;
  voidLookups: number;
  cadeia: string[];
  /** true quando o SPF delega a decisão para outro domínio, via redirect. */
  redireciona: boolean;
  erros: string[];
  avisos: string[];
}

export interface LeitorDns {
  txt: (nome: string) => Promise<string[]>;
  mx: (nome: string) => Promise<ServidorMx[]>;
  a: (nome: string) => Promise<string[]>;
}

const NOMES = ["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect"];

export function extrairSpf(registros: string[]): string[] {
  return registros.map((r) => r.trim()).filter((r) => /^v=spf1(\s|$)/i.test(r));
}

function lerMecanismo(token: string): Mecanismo | null {
  const achado = /^([+\-~?])?([a-z0-9]+)(?::(\S+))?$/i.exec(token.trim());
  if (!achado) return null;

  const [, qualificador = "+", nomeBruto = "", valor] = achado;
  const nome = nomeBruto.toLowerCase();
  if (!NOMES.includes(nome)) return null;

  if (nome === "redirect") return { bruto: token, qualificador, nome, valor: valor ?? null };
  return { bruto: token, qualificador, nome, valor: valor ?? null };
}

interface Estado {
  mecanismos: Mecanismo[];
  consultas: number;
  voidLookups: number;
  cadeia: string[];
  erros: string[];
  avisos: string[];
  qualificadorAll: string | null;
  redireciona: boolean;
}

async function percorrer(
  nome: string,
  leitor: LeitorDns,
  estado: Estado,
  profundidade: number,
  visitados: Set<string>,
): Promise<void> {
  if (profundidade > 10) {
    estado.erros.push(`cadeia de include: passou de 10 níveis em ${nome}`);
    return;
  }
  if (visitados.has(nome)) return;
  visitados.add(nome);

  const registros = extrairSpf(await leitor.txt(nome));

  if (registros.length === 0) {
    if (profundidade === 0) estado.erros.push(`${nome} não tem registro SPF`);
    else {
      estado.voidLookups++;
      estado.erros.push(`include:${nome} não leva a nenhum SPF, então essa consulta não libera nada`);
    }
    return;
  }

  if (registros.length > 1 && profundidade === 0) {
    estado.erros.push(`${nome} publica mais de um registro SPF, e os sistemas usam apenas o primeiro`);
  }

  const registro = registros[0] ?? "";
  estado.cadeia.push(registro);

  const tokens = registro.split(/\s+/).filter(Boolean).slice(1);
  let depoisDoAll = false;

  for (const token of tokens) {
    // redirect= substitui o all: quem decide o resultado é o SPF do outro domínio.
    const redirecionamento = /^redirect=(.+)$/i.exec(token);
    if (redirecionamento) {
      const alvo = redirecionamento[1] ?? "";
      estado.mecanismos.push({ bruto: token, qualificador: "", nome: "redirect", valor: alvo });
      estado.consultas++;
      estado.redireciona = true;
      if (alvo) await percorrer(alvo, leitor, estado, profundidade + 1, visitados);
      continue;
    }

    const mecanismo = lerMecanismo(token);
    if (!mecanismo) {
      estado.erros.push(`não entendi o termo "${token}" no SPF de ${nome}`);
      continue;
    }

    estado.mecanismos.push(mecanismo);

    if (mecanismo.nome === "all") {
      estado.qualificadorAll = mecanismo.qualificador;
      if (tokens.indexOf(token) < tokens.length - 1) depoisDoAll = true;
      continue;
    }

    if (mecanismo.nome === "include" || mecanismo.nome === "redirect") {
      estado.consultas++;
      const alvo = mecanismo.valor ?? "";
      if (!alvo) {
        estado.erros.push(`${mecanismo.nome} sem domínio no SPF de ${nome}`);
        continue;
      }
      await percorrer(alvo, leitor, estado, profundidade + 1, visitados);
      continue;
    }

    if (mecanismo.nome === "a" || mecanismo.nome === "mx" || mecanismo.nome === "ptr" || mecanismo.nome === "exists") {
      estado.consultas++;
      const alvo = mecanismo.valor?.split("/")[0] ?? nome;
      const fazConsulta =
        mecanismo.nome === "mx" ? await leitor.mx(alvo) : mecanismo.nome === "ptr" ? alvo : await leitor.a(alvo);
      const vazio = Array.isArray(fazConsulta) ? fazConsulta.length === 0 : false;
      if (vazio) estado.voidLookups++;
      continue;
    }

    // ip4 e ip6 não consultam DNS, então não entram na conta.
  }

  if (depoisDoAll) {
    estado.avisos.push(`o SPF de ${nome} tem termos depois do all, e eles nunca chegam a ser avaliados`);
  }
}

export async function analisarSpf(dominio: string, leitor: LeitorDns): Promise<AnaliseSpf> {
  const estado: Estado = {
    mecanismos: [],
    consultas: 0,
    voidLookups: 0,
    cadeia: [],
    erros: [],
    avisos: [],
    qualificadorAll: null,
    redireciona: false,
  };

  await percorrer(dominio, leitor, estado, 0, new Set());
  const raiz = extrairSpf(await leitor.txt(dominio));

  if (estado.consultas > LIMITE_CONSULTAS) {
    estado.erros.push(
      `o SPF gasta ${estado.consultas} consultas DNS e o limite é ${LIMITE_CONSULTAS}: quem passa do limite recebe falha permanente, o que derruba o envio legítimo`,
    );
  }
  if (estado.voidLookups > 2) {
    estado.erros.push(`${estado.voidLookups} consultas do SPF não devolvem nada, e o limite para isso é 2`);
  }
  if (estado.mecanismos.some((m) => m.nome === "ptr")) {
    estado.avisos.push("o SPF usa ptr, mecanismo que os guias atuais pedem para evitar por ser lento e frágil");
  }

  return {
    registros: raiz,
    mecanismos: estado.mecanismos,
    qualificadorAll: estado.qualificadorAll,
    consultas: estado.consultas,
    voidLookups: estado.voidLookups,
    cadeia: estado.cadeia,
    redireciona: estado.redireciona,
    erros: estado.erros,
    avisos: estado.avisos,
  };
}
