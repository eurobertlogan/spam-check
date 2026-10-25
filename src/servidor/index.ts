/**
 * Servidor local da página de diagnóstico.
 *
 *   npm start                 # compila e sobe em http://localhost:4331
 *   npm start -- --porta 5000
 *
 * As regras do diagnóstico vivem em src/nucleo e não sabem que existe uma
 * interface. Aqui só entra o transporte: receber o domínio, chamar o núcleo e
 * devolver o resultado para a página desenhar.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { diagnosticar } from "../nucleo/diagnostico.js";

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const PUBLICO = join(RAIZ, "public");
const NAVEGADOR = join(RAIZ, "dist", "navegador");

const argumentos = process.argv.slice(2);
const lerArg = (nome: string, padrao: string): string => {
  const indice = argumentos.indexOf(`--${nome}`);
  const valor = indice !== -1 ? argumentos[indice + 1] : undefined;
  return valor && !valor.startsWith("--") ? valor : padrao;
};

const porta = Number(lerArg("porta", process.env.PORT ?? "4331"));
const host = lerArg("host", "127.0.0.1");

const TIPOS: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

async function servirArquivo(raiz: string, relativo: string, resposta: ServerResponse): Promise<boolean> {
  const limpo = normalize(relativo).replace(/^(\.\.[/\\])+/, "");
  const caminho = join(raiz, limpo);
  if (!caminho.startsWith(raiz)) {
    resposta.writeHead(403).end("fora da pasta");
    return true;
  }
  try {
    const conteudo = await readFile(caminho);
    resposta.writeHead(200, {
      "content-type": TIPOS[extname(caminho).toLowerCase()] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    resposta.end(conteudo);
    return true;
  } catch {
    return false;
  }
}

function responderJson(resposta: ServerResponse, status: number, corpo: unknown): void {
  resposta.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  resposta.end(JSON.stringify(corpo));
}

function lerCorpo(requisicao: IncomingMessage): Promise<string> {
  return new Promise((resolver, rejeitar) => {
    const partes: Buffer[] = [];
    requisicao.on("data", (parte: Buffer) => {
      partes.push(parte);
      if (Buffer.concat(partes).length > 16 * 1024) {
        rejeitar(new Error("corpo grande demais"));
        requisicao.destroy();
      }
    });
    requisicao.on("end", () => resolver(Buffer.concat(partes).toString("utf8")));
    requisicao.on("error", rejeitar);
  });
}

const servidor = createServer(async (requisicao, resposta) => {
  const metodo = requisicao.method ?? "GET";
  const alvo = new URL(requisicao.url ?? "/", "http://localhost");
  const caminho = decodeURIComponent(alvo.pathname);

  if (caminho === "/api/diagnostico") {
    try {
      const corpo = metodo === "POST" ? (JSON.parse(await lerCorpo(requisicao)) as { dominio?: string }) : {};
      const dominio = String(corpo.dominio ?? alvo.searchParams.get("dominio") ?? "").trim();

      if (!dominio) {
        responderJson(resposta, 400, { erro: "informe o domínio" });
        return;
      }
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(dominio)) {
        responderJson(resposta, 400, { erro: `"${dominio}" não parece um domínio. Tente algo como exemplo.com` });
        return;
      }

      responderJson(resposta, 200, await diagnosticar(dominio));
    } catch (falha) {
      responderJson(resposta, 400, { erro: (falha as Error).message });
    }
    return;
  }

  if (metodo !== "GET") {
    resposta.writeHead(405).end("método não permitido");
    return;
  }

  if (caminho === "/" || caminho === "/index.html") {
    await servirArquivo(PUBLICO, "index.html", resposta);
    return;
  }

  for (const raiz of [PUBLICO, NAVEGADOR]) {
    if (await servirArquivo(raiz, caminho.replace(/^\/+/, ""), resposta)) return;
  }

  resposta.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  resposta.end(`não encontrei ${caminho}`);
});

servidor.listen(porta, host, () => {
  console.log(`spam-check em http://${host}:${porta}`);
  console.log("digite o domínio na página e clique em verificar");
});
