/**
 * Camada de DNS com limite de tempo e cache.
 *
 * Toda pergunta passa por aqui. O cache evita repetir a mesma consulta quando o
 * SPF inclui o mesmo domínio por dois caminhos, e o limite de tempo evita que um
 * servidor lento deixe o diagnóstico pendurado.
 */
import { Resolver } from "node:dns/promises";

export interface ServidorMx {
  prioridade: number;
  host: string;
}

const SEM_REGISTRO = new Set(["ENODATA", "ENOTFOUND", "NXDOMAIN"]);

const codigoDe = (falha: unknown): string => (falha as { code?: string }).code ?? "";

export class Consultas {
  #resolvedor = new Resolver();
  #cache = new Map<string, Promise<unknown>>();
  #limiteMs: number;

  consultas = 0;
  falhas: string[] = [];

  constructor(servidores: string[] = [], limiteMs = 6000) {
    if (servidores.length) this.#resolvedor.setServers(servidores);
    this.#limiteMs = limiteMs;
  }

  #comCache<T>(chave: string, buscar: () => Promise<T>, padrao: T): Promise<T> {
    const guardado = this.#cache.get(chave);
    if (guardado) return guardado as Promise<T>;

    const promessa = (async (): Promise<T> => {
      this.consultas++;
      let relogio: NodeJS.Timeout | undefined;
      try {
        const limite = new Promise<never>((_, rejeitar) => {
          relogio = setTimeout(() => rejeitar(new Error("tempo esgotado")), this.#limiteMs);
        });
        return await Promise.race([buscar(), limite]);
      } catch (falha) {
        const codigo = codigoDe(falha);
        if (SEM_REGISTRO.has(codigo)) return padrao;
        const motivo = codigo || (falha as Error).message;
        if (motivo === "tempo esgotado") this.falhas.push(`${chave}: ${motivo}`);
        return padrao;
      } finally {
        if (relogio) clearTimeout(relogio);
      }
    })();

    this.#cache.set(chave, promessa);
    return promessa;
  }

  /** Registros TXT, já sem as quebras de linha que o DNS usa para separar pedaços. */
  txt(nome: string): Promise<string[]> {
    return this.#comCache(`TXT ${nome}`, async () => {
      const linhas = await this.#resolvedor.resolveTxt(nome);
      return linhas.map((pedacos) => pedacos.join(""));
    }, []);
  }

  mx(nome: string): Promise<ServidorMx[]> {
    return this.#comCache(`MX ${nome}`, async () => {
      const registros = await this.#resolvedor.resolveMx(nome);
      return registros.map((r) => ({ prioridade: r.priority, host: r.exchange.replace(/\.$/, "") }));
    }, []);
  }

  a(nome: string): Promise<string[]> {
    return this.#comCache(`A ${nome}`, () => this.#resolvedor.resolve4(nome), []);
  }

  aaaa(nome: string): Promise<string[]> {
    return this.#comCache(`AAAA ${nome}`, () => this.#resolvedor.resolve6(nome), []);
  }

  /** Reverso: o nome que o IP anuncia de volta. */
  ptr(ip: string): Promise<string[]> {
    const invertido = ip.split(".").reverse().join(".") + ".in-addr.arpa";
    return this.#comCache(`PTR ${ip}`, async () => {
      const nomes = await this.#resolvedor.resolvePtr(invertido);
      // Alguns provedores devolvem o próprio nome invertido como se fosse o
      // reverso. Isso não é nome utilizável, então tratamos como ausente.
      return nomes
        .map((n) => n.replace(/\.$/, ""))
        .filter((n) => n.toLowerCase() !== invertido.toLowerCase());
    }, []);
  }

  /** Consulta de lista de bloqueio: responde quando o IP está listado. */
  listado(ip: string, zona: string): Promise<string | null> {
    const invertido = ip.split(".").reverse().join(".");
    return this.#comCache(`BL ${zona} ${ip}`, async () => {
      const resposta = await this.#resolvedor.resolve4(`${invertido}.${zona}`);
      return resposta[0] ?? null;
    }, null);
  }
}
