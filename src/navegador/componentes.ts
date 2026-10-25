/**
 * Componentes da página.
 *
 * Cada pedaço do diagnóstico é montado por uma função que devolve elemento, sem
 * string de HTML solta no meio do código. Isso mantém o texto vindo do DNS sempre
 * tratado como texto, nunca como marcação.
 */
import type { Achado, Bloco, Nivel, Resultado } from "./tipos.js";

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  classe?: string,
  texto?: string,
): HTMLElementTagNameMap[K] {
  const no = document.createElement(tag);
  if (classe) no.className = classe;
  if (texto !== undefined) no.textContent = texto;
  return no;
}

const ROTULO: Record<Nivel, string> = { erro: "erro", aviso: "aviso", ok: "ok", info: "info" };

function contador(classe: string, valor: number | string, rotulo: string, zerado = false): HTMLElement {
  const caixa = el("div", `contador ${classe}${zerado ? " zero" : ""}`);
  caixa.append(el("b", undefined, String(valor)), el("span", undefined, rotulo));
  return caixa;
}

export function placar(resultado: Resultado): HTMLElement {
  const erros = resultado.achados.filter((a) => a.nivel === "erro").length;
  const avisos = resultado.achados.filter((a) => a.nivel === "aviso").length;
  const oks = resultado.achados.filter((a) => a.nivel === "ok").length;

  const caixa = el("section", `placar ${resultado.nota >= 7 ? "bom" : resultado.nota >= 4 ? "medio" : "ruim"}`);
  const nota = el("div", "nota");
  nota.append(el("b", undefined, String(resultado.nota)), el("span", undefined, "de 10"));

  const texto = el("div", "veredito");
  texto.append(el("p", "frase", resultado.veredito));
  texto.append(
    el(
      "p",
      "detalhe",
      `${resultado.consultas} consultas DNS em ${resultado.duracaoMs} ms, lidas do DNS público em ${new Date(
        resultado.quando,
      ).toLocaleString("pt-BR")}`,
    ),
  );

  const contadores = el("div", "contadores");
  contadores.append(
    contador("erros", erros, erros === 1 ? "erro" : "erros", erros === 0),
    contador("avisos", avisos, avisos === 1 ? "aviso" : "avisos", avisos === 0),
    contador("checks", oks, "verificações ok", oks === 0),
  );

  caixa.append(nota, texto, contadores);
  return caixa;
}

function achado(item: Achado): HTMLElement {
  const linha = el("li", `achado ${item.nivel}`);
  linha.append(el("span", "rotulo", ROTULO[item.nivel]));
  const corpo = el("div", "corpo");
  corpo.append(el("p", "mensagem", item.mensagem));
  if (item.correcao) corpo.append(el("p", "correcao", `correção: ${item.correcao}`));
  linha.append(corpo);
  return linha;
}

export function blocoDiagnostico(bloco: Bloco): HTMLElement {
  const caixa = el("section", "bloco");
  caixa.append(el("h2", undefined, bloco.titulo));

  const lista = el("ul", "achados");
  for (const item of bloco.achados) lista.append(achado(item));
  caixa.append(lista);

  if (bloco.registros.length > 0) {
    const detalhes = el("details");
    detalhes.append(el("summary", undefined, `Registros encontrados (${bloco.registros.length})`));
    const pre = el("pre");
    pre.textContent = bloco.registros.join("\n");
    detalhes.append(pre);
    caixa.append(detalhes);
  }

  return caixa;
}

export function desenharResultado(container: HTMLElement, resultado: Resultado): void {
  container.replaceChildren(placar(resultado), ...resultado.blocos.map(blocoDiagnostico));
}

/** Botão com ação, usado na barra de exportar. */
export function botao(rotulo: string, acao: () => void, classe = "secundario"): HTMLButtonElement {
  const elemento = el("button", classe, rotulo);
  elemento.type = "button";
  elemento.addEventListener("click", acao);
  return elemento;
}
