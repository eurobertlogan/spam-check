#!/usr/bin/env node
/**
 * Entrada do comando.
 *
 *   spam-check exemplo.com
 *   spam-check exemplo.com --json
 */
import { diagnosticar } from "../nucleo/diagnostico.js";
import { textoDoResultado } from "./relatorio-texto.js";

const VERSAO = "1.0.0";

const AJUDA = `spam-check ${VERSAO}

Verifica por que o email do seu domínio cai no spam, lendo o DNS público.
A mesma verificação, com página e exportação, roda em npm start.

uso:
  spam-check <domínio> [opções]

opções:
  --json                  imprime o resultado cru em JSON
  --seletores a,b,c       seletores de DKIM a testar, além dos comuns
  --resolvedor <ip>       servidor DNS a usar, pode repetir
  --limite <ms>           tempo máximo por consulta (padrão 6000)
  --sem-cor               saída sem cor
  --ajuda                 esta mensagem

exemplo:
  spam-check exemplo.com
`;

const argumentos = process.argv.slice(2);
const pegarValor = (nome: string): string | null => {
  const indice = argumentos.indexOf(nome);
  if (indice === -1) return null;
  const valor = argumentos[indice + 1];
  return valor && !valor.startsWith("--") ? valor : "";
};

const repetidos = (nome: string): string[] => {
  const valores: string[] = [];
  argumentos.forEach((arg, indice) => {
    if (arg === nome) {
      const valor = argumentos[indice + 1];
      if (valor && !valor.startsWith("--")) valores.push(valor);
    }
  });
  return valores;
};

/** Opções que consomem o argumento seguinte, para não confundir valor com domínio. */
const COM_VALOR = new Set(["--seletores", "--resolvedor", "--limite"]);

function acharDominio(): string | null {
  for (let i = 0; i < argumentos.length; i++) {
    const arg = argumentos[i] ?? "";
    if (COM_VALOR.has(arg)) {
      i++;
      continue;
    }
    if (!arg.startsWith("-")) return arg;
  }
  return null;
}

async function principal(): Promise<void> {
  if (argumentos.includes("--ajuda") || argumentos.includes("-h")) {
    console.log(AJUDA.trim());
    return;
  }

  if (argumentos.length === 0) {
    console.log(AJUDA.trim());
    process.exitCode = 1;
    return;
  }

  if (argumentos.includes("--versao") || argumentos.includes("-v")) {
    console.log(VERSAO);
    return;
  }

  const dominio = acharDominio();

  if (!dominio) {
    console.error("informe o domínio. Exemplo: spam-check exemplo.com");
    process.exitCode = 1;
    return;
  }

  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(dominio)) {
    console.error(`"${dominio}" não parece um domínio. Informe algo como exemplo.com`);
    process.exitCode = 1;
    return;
  }

  const seletores = pegarValor("--seletores");
  const limite = Number(pegarValor("--limite") ?? "0");
  const resolvedores = repetidos("--resolvedor").flatMap((r) => r.split(","));
  const querJson = argumentos.includes("--json");
  const semCor = argumentos.includes("--sem-cor") || !process.stdout.isTTY;

  const resultado = await diagnosticar(dominio, {
    seletores: seletores ? seletores.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
    resolvedores,
    limiteMs: limite > 0 ? limite : undefined,
  });

  if (querJson) {
    console.log(JSON.stringify(resultado, null, 2));
  } else {
    console.log(textoDoResultado(resultado, !semCor));
    console.log(`\npara ver a página com exportação: npm start`);
  }

  process.exitCode = resultado.achados.some((a) => a.nivel === "erro") ? 1 : 0;
}

principal().catch((falha) => {
  console.error(`falhou: ${(falha as Error).message}`);
  process.exitCode = 1;
});
