/** Tipos que espelham a resposta do servidor, para o navegador compilar sozinho. */

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

export interface RespostaErro {
  erro: string;
}
