/** Saída legível no terminal. O relatório em página é montado pelo navegador. */
import type { Resultado } from "../nucleo/tipos.js";

const CORES: Record<string, string> = {
  erro: "\u001b[31m",
  aviso: "\u001b[33m",
  ok: "\u001b[32m",
  info: "\u001b[90m",
  fim: "\u001b[0m",
  forte: "\u001b[1m",
  fraco: "\u001b[90m",
};

const ROTULO: Record<string, string> = { erro: "erro", aviso: "aviso", ok: "ok", info: "info" };

export function textoDoResultado(resultado: Resultado, comCor = true): string {
  const c = (chave: string): string => (comCor ? (CORES[chave] ?? "") : "");
  const linhas: string[] = [];

  linhas.push(`${c("forte")}spam-check ${resultado.dominio}${c("fim")}`);
  linhas.push("");

  for (const bloco of resultado.blocos) {
    for (const achado of bloco.achados) {
      const area = bloco.area.padEnd(10);
      linhas.push(`${area}${c(achado.nivel)}${ROTULO[achado.nivel]?.padEnd(6) ?? ""}${c("fim")}${achado.mensagem}`);
      if (achado.correcao) linhas.push(`${" ".repeat(10)}${c("fraco")}correção: ${achado.correcao}${c("fim")}`);
    }
  }

  linhas.push("");
  const corDaNota = resultado.nota >= 7 ? c("ok") : resultado.nota >= 4 ? c("aviso") : c("erro");
  linhas.push(`${c("forte")}nota ${corDaNota}${resultado.nota} de 10${c("fim")} ${resultado.veredito}`);
  linhas.push(
    `${c("fraco")}${resultado.consultas} consultas DNS em ${resultado.duracaoMs} ms${c("fim")}`,
  );

  const erros = resultado.achados.filter((a) => a.nivel === "erro").length;
  if (erros > 0) {
    linhas.push("");
    linhas.push(
      `${c("fraco")}O que resolver primeiro:${c("fim")} ${resultado.achados
        .filter((a) => a.nivel === "erro")
        .map((a) => a.area)
        .filter((area, i, lista) => lista.indexOf(area) === i)
        .join(", ")}`,
    );
  }

  return linhas.join("\n");
}
