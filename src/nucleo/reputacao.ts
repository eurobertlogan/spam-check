/**
 * Reputação do servidor que recebe o seu email.
 *
 * Quem envia para o seu domínio conecta no servidor apontado pelo MX. Se esse
 * endereço estiver numa lista de bloqueio, ou não tiver nome reverso, a mensagem
 * cai antes de qualquer análise de conteúdo.
 */
import type { Consultas, ServidorMx } from "./dns.js";

export interface Zona {
  zona: string;
  nome: string;
  codigos: Record<string, string>;
}

export const ZONAS: Zona[] = [
  {
    zona: "zen.spamhaus.org",
    nome: "Spamhaus ZEN",
    codigos: {
      "127.0.0.2": "listado como fonte de spam",
      "127.0.0.3": "listado por enviar spam diretamente",
      "127.0.0.4": "listado por exploração ou máquina comprometida",
      "127.0.0.9": "listado como faixa que não deveria enviar email",
      "127.0.0.10": "listado como faixa de acesso residencial",
      "127.0.0.11": "listado como faixa de acesso residencial",
    },
  },
  {
    zona: "bl.spamcop.net",
    nome: "SpamCop",
    codigos: { "127.0.0.2": "listado por reclamações de spam" },
  },
  {
    zona: "b.barracudacentral.org",
    nome: "Barracuda",
    codigos: { "127.0.0.2": "listado pela Barracuda" },
  },
  {
    zona: "dnsbl.dronebl.org",
    nome: "DroneBL",
    codigos: {
      "127.0.0.2": "listado como proxy aberto",
      "127.0.0.3": "listado como máquina comprometida",
      "127.0.0.8": "listado como proxy de rede",
    },
  },
];

export interface Listagem {
  zona: string;
  nome: string;
  codigo: string;
  significado: string;
}

export interface IpAnalisado {
  ip: string;
  reverso: string | null;
  listagens: Listagem[];
  listasConsultadas: number;
  listasIndisponiveis: string[];
}

export interface AnaliseReputacao {
  servidores: { host: string; prioridade: number; ips: IpAnalisado[] }[];
  semIp: string[];
}

export async function analisarReputacao(
  servidores: ServidorMx[],
  consultas: Consultas,
): Promise<AnaliseReputacao> {
  const semIp: string[] = [];

  const analisados = await Promise.all(
    servidores.map(async (servidor) => {
      const enderecos = await consultas.a(servidor.host);
      if (enderecos.length === 0) semIp.push(servidor.host);

      const ips = await Promise.all(
        enderecos.slice(0, 2).map(async (ip): Promise<IpAnalisado> => {
          const [reversos, listagens] = await Promise.all([
            consultas.ptr(ip),
            Promise.all(
              ZONAS.map(async (zona) => {
                const resposta = await consultas.listado(ip, zona.zona);
                if (!resposta) return null;
                return {
                  zona: zona.zona,
                  nome: zona.nome,
                  codigo: resposta,
                  significado: zona.codigos[resposta] ?? "listado",
                } satisfies Listagem;
              }),
            ),
          ]);

          const encontradas = listagens.filter((l): l is Listagem => l !== null);
          const indisponiveis = consultas.falhas
            .filter((f) => f.includes(ip))
            .map((f) => f.split(":")[0] ?? f);

          return {
            ip,
            reverso: reversos[0] ?? null,
            listagens: encontradas,
            listasConsultadas: ZONAS.length,
            listasIndisponiveis: indisponiveis,
          };
        }),
      );

      return { host: servidor.host, prioridade: servidor.prioridade, ips };
    }),
  );

  return { servidores: analisados, semIp };
}
