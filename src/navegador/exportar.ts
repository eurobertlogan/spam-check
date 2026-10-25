/**
 * Exportação do diagnóstico.
 *
 * A página exportada é um arquivo único, com o estilo embutido, que abre em
 * qualquer navegador e imprime bem. Serve para mandar para quem cuida da zona
 * DNS, que costuma querer um documento e não uma janela de terminal.
 */
import type { Nivel, Resultado } from "./tipos.js";

const ROTULO: Record<Nivel, string> = { erro: "erro", aviso: "aviso", ok: "ok", info: "info" };

const escapar = (texto: string): string =>
  texto
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

const ESTILO = `
  :root { color-scheme: light dark; --texto: #1b1f24; --fraco: #5c6672; --borda: #dfe3e8; --fundo: #fff;
          --erro: #b3261e; --aviso: #8a6100; --ok: #14663c; }
  @media (prefers-color-scheme: dark) {
    :root { --texto: #e8eaed; --fraco: #98a1ac; --borda: #2c3138; --fundo: #131619;
            --erro: #ff8a80; --aviso: #e3b341; --ok: #7ee2a8; }
  }
  * { box-sizing: border-box; }
  body { margin: 0 auto; max-width: 820px; padding: 56px 28px 96px; background: var(--fundo); color: var(--texto);
         font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  header { border-bottom: 1px solid var(--borda); padding-bottom: 22px; }
  h1 { margin: 0 0 6px; font-size: 22px; font-weight: 600; }
  .dominio { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .metadados { color: var(--fraco); font-size: 13.5px; margin: 0; }
  .placar { display: flex; align-items: baseline; gap: 22px; flex-wrap: wrap; margin: 28px 0 6px; padding: 20px 22px;
            border: 1px solid var(--borda); border-radius: 12px; }
  .placar .nota b { font-size: 40px; font-weight: 600; line-height: 1; }
  .placar .nota span { color: var(--fraco); margin-left: 6px; font-size: 13px; }
  .placar .frase { margin: 0; font-size: 16px; }
  .placar .detalhe { margin: 4px 0 0; color: var(--fraco); font-size: 13px; }
  .placar.bom .nota b { color: var(--ok); }
  .placar.medio .nota b { color: var(--aviso); }
  .placar.ruim .nota b { color: var(--erro); }
  h2 { font-size: 12.5px; text-transform: uppercase; letter-spacing: .09em; color: var(--fraco); margin: 38px 0 10px; }
  .achados { list-style: none; margin: 0; padding: 0; border: 1px solid var(--borda); border-radius: 10px; overflow: hidden; }
  .achado { display: flex; gap: 14px; padding: 12px 15px; border-bottom: 1px solid var(--borda); }
  .achado:last-child { border-bottom: 0; }
  .achado .rotulo { flex: 0 0 50px; font-size: 10.5px; font-weight: 700; letter-spacing: .06em;
                    text-transform: uppercase; padding-top: 4px; }
  .achado.erro .rotulo { color: var(--erro); }
  .achado.aviso .rotulo { color: var(--aviso); }
  .achado.ok .rotulo { color: var(--ok); }
  .achado.info .rotulo { color: var(--fraco); }
  .achado p { margin: 0; }
  .achado .correcao { color: var(--fraco); font-size: 13.5px; margin-top: 4px; }
  details { margin-top: 10px; }
  summary { cursor: pointer; color: var(--fraco); font-size: 13.5px; }
  pre { background: rgba(127,127,127,.09); padding: 14px; border-radius: 8px; overflow-x: auto;
        font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; word-break: break-all; }
  footer { margin-top: 52px; padding-top: 16px; border-top: 1px solid var(--borda); color: var(--fraco); font-size: 13px; }
  @media print { body { padding: 0; } .placar, .achados { break-inside: avoid; } details[open] pre { break-inside: avoid; } }
`;

export function documentoAutocontido(resultado: Resultado): string {
  const erros = resultado.achados.filter((a) => a.nivel === "erro").length;
  const avisos = resultado.achados.filter((a) => a.nivel === "aviso").length;
  const classe = resultado.nota >= 7 ? "bom" : resultado.nota >= 4 ? "medio" : "ruim";

  const blocos = resultado.blocos
    .map((bloco) => {
      const achados = bloco.achados
        .map(
          (item) => `<li class="achado ${item.nivel}">
        <span class="rotulo">${ROTULO[item.nivel]}</span>
        <div>
          <p>${escapar(item.mensagem)}</p>
          ${item.correcao ? `<p class="correcao">correção: ${escapar(item.correcao)}</p>` : ""}
        </div>
      </li>`,
        )
        .join("");

      const registros = bloco.registros.length
        ? `<details><summary>Registros encontrados (${bloco.registros.length})</summary><pre>${escapar(
            bloco.registros.join("\n"),
          )}</pre></details>`
        : "";

      return `<h2>${escapar(bloco.titulo)}</h2>\n<ul class="achados">${achados}</ul>\n${registros}`;
    })
    .join("\n");

  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Diagnóstico de email: ${escapar(resultado.dominio)}</title>
<style>${ESTILO}</style>
</head>
<body>
<header>
  <h1>Diagnóstico de email: <span class="dominio">${escapar(resultado.dominio)}</span></h1>
  <p class="metadados">Lido do DNS público em ${escapar(new Date(resultado.quando).toLocaleString("pt-BR"))}, em ${
    resultado.duracaoMs
  } ms e ${resultado.consultas} consultas.</p>
</header>
<div class="placar ${classe}">
  <div class="nota"><b>${resultado.nota}</b><span>de 10</span></div>
  <div>
    <p class="frase">${escapar(resultado.veredito)}</p>
    <p class="detalhe">${erros} erro(s) e ${avisos} aviso(s). Erro quebra a entrega, aviso degrada.</p>
  </div>
</div>
${blocos}
<footer>Gerado por spam-check a partir do DNS público. Listas de bloqueio e provedores guardam histórico: depois de corrigir, a melhora leva alguns dias para aparecer.</footer>
</body>
</html>
`;
}

export function baixar(nome: string, conteudo: string, tipo = "text/html;charset=utf-8"): void {
  const endereco = URL.createObjectURL(new Blob([conteudo], { type: tipo }));
  const ligacao = document.createElement("a");
  ligacao.href = endereco;
  ligacao.download = nome;
  document.body.append(ligacao);
  ligacao.click();
  ligacao.remove();
  URL.revokeObjectURL(endereco);
}
