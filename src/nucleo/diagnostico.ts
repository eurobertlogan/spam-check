/**
 * Junta tudo: lê o DNS do domínio e devolve o diagnóstico pronto.
 */
import { Consultas } from "./dns.js";
import { analisarSpf } from "./spf.js";
import { analisarDkim, SELETOR_SONDA, SELETORES_COMUNS } from "./dkim.js";
import { analisarDmarc } from "./dmarc.js";
import { analisarReputacao } from "./reputacao.js";
import { avaliar } from "./avaliar.js";
import type { Achado, Bloco, Resultado } from "./tipos.js";

export interface OpcoesDiagnostico {
  seletores?: string[];
  resolvedores?: string[];
  limiteMs?: number;
}

export async function diagnosticar(dominio: string, opcoes: OpcoesDiagnostico = {}): Promise<Resultado> {
  const inicio = Date.now();
  const consultas = new Consultas(opcoes.resolvedores ?? [], opcoes.limiteMs);
  const limpo = dominio.trim().toLowerCase().replace(/\.$/, "");

  // O MX vem primeiro porque a leitura da reputação depende dele. Um MX nulo
  // ("0 .") é a forma padrão de dizer que o domínio não recebe email, e nesse
  // caso não há servidor de entrada para avaliar.
  const mx = await consultas.mx(limpo);
  const mxEfetivo = mx.filter((m) => m.host && m.host !== ".");
  const seletores = opcoes.seletores ?? SELETORES_COMUNS;

  const [spf, dkim, sonda, dmarc, enderecosDoDominio] = await Promise.all([
    analisarSpf(limpo, consultas),
    analisarDkim(limpo, seletores, (nome) => consultas.txt(nome)),
    analisarDkim(limpo, [SELETOR_SONDA], (nome) => consultas.txt(nome)),
    analisarDmarc(limpo, consultas),
    consultas.a(limpo),
  ]);

  const reputacao = await analisarReputacao(mxEfetivo, consultas);
  const { achados, nota, veredito } = avaliar({
    dominio: limpo,
    mx,
    spf,
    dkim: { publicados: dkim.publicados, tentados: seletores, curinga: sonda.publicados.length > 0 },
    dmarc,
    reputacao,
    enderecosDoDominio,
  });

  const blocos: Bloco[] = [
    {
      area: "MX",
      titulo: "Servidores de entrada",
      registros: mx.map((m) => `${m.prioridade} ${m.host}`),
      achados: achados.filter((a) => a.area === "MX"),
    },
    {
      area: "SPF",
      titulo: "SPF",
      registros: spf.cadeia,
      achados: achados.filter((a) => a.area === "SPF"),
    },
    {
      area: "DKIM",
      titulo: "DKIM",
      registros: dkim.publicados.map((d) => `${d.seletor}: ${d.bruto ?? ""}`),
      achados: achados.filter((a) => a.area === "DKIM"),
    },
    {
      area: "DMARC",
      titulo: "DMARC",
      registros: dmarc.registros,
      achados: achados.filter((a) => a.area === "DMARC"),
    },
    {
      area: "Reputação",
      titulo: "Reputação dos servidores",
      registros: reputacao.servidores.flatMap((s) =>
        s.ips.map((ip) => `${s.host} ${ip.ip}${ip.reverso ? ` (${ip.reverso})` : " (sem reverso)"}`),
      ),
      achados: achados.filter((a) => a.area === "Reputação"),
    },
  ];

  const avisosDoDominio: Achado[] = achados.filter((a) => a.area === "Domínio");
  if (avisosDoDominio.length > 0) {
    blocos.push({
      area: "Domínio",
      titulo: "Domínio",
      registros: enderecosDoDominio,
      achados: avisosDoDominio,
    });
  }

  return {
    dominio: limpo,
    nota,
    veredito,
    achados,
    blocos: blocos.filter((b) => b.achados.length > 0 || b.registros.length > 0),
    consultas: consultas.consultas,
    duracaoMs: Date.now() - inicio,
    quando: new Date().toISOString(),
  };
}
