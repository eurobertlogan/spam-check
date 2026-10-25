/** Tipos compartilhados do diagnóstico. */

export type Nivel = "erro" | "aviso" | "ok" | "info";

export interface Achado {
  area: string;
  nivel: Nivel;
  mensagem: string;
  correcao?: string;
}

export interface Bloco {
  area: string;
  titulo: string;
  /** Linhas cruas do que foi encontrado no DNS, para quem quiser ver a origem. */
  registros: string[];
  achados: Achado[];
}

export interface Resultado {
  dominio: string;
  nota: number;
  veredito: string;
  achados: Achado[];
  blocos: Bloco[];
  consultas: number;
  duracaoMs: number;
  quando: string;
}

export const CONTAGEM = (achados: Achado[]): { erros: number; avisos: number } => ({
  erros: achados.filter((a) => a.nivel === "erro").length,
  avisos: achados.filter((a) => a.nivel === "aviso").length,
});
