/** Comportamento da página: digita o domínio, clica em verificar, vê o diagnóstico. */
import { botao, desenharResultado, el } from "./componentes.js";
import { baixar, documentoAutocontido } from "./exportar.js";
import type { RespostaErro, Resultado } from "./tipos.js";

const formulario = document.getElementById("form") as HTMLFormElement;
const campo = document.getElementById("dominio") as HTMLInputElement;
const verificar = document.getElementById("verificar") as HTMLButtonElement;
const status = document.getElementById("status") as HTMLElement;
const painel = document.getElementById("painel") as HTMLElement;
const acoes = document.getElementById("acoes") as HTMLElement;
const resultado = document.getElementById("resultado") as HTMLElement;

let ultimo: Resultado | null = null;

function definirStatus(mensagem: string | null, tipo: "erro" | "info" = "erro"): void {
  status.textContent = mensagem ?? "";
  status.hidden = mensagem === null;
  status.className = `status ${tipo}`;
}

function montarAcoes(): void {
  acoes.replaceChildren(
    botao("Exportar página", () => {
      if (!ultimo) return;
      baixar(`${ultimo.dominio}.html`, documentoAutocontido(ultimo));
    }, "principal"),
    botao("Copiar JSON", () => {
      if (!ultimo) return;
      void navigator.clipboard
        .writeText(JSON.stringify(ultimo, null, 2))
        .then(() => definirStatus("JSON copiado para a área de transferência", "info"))
        .catch(() => definirStatus("não consegui copiar, o navegador bloqueou o acesso"));
    }),
    botao("Verificar de novo", () => void verificarDominio(ultimo?.dominio ?? campo.value)),
  );
}

async function verificarDominio(dominio: string): Promise<void> {
  verificar.disabled = true;
  verificar.textContent = "verificando...";
  definirStatus(null);
  painel.hidden = true;

  try {
    const resposta = await fetch("/api/diagnostico", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ dominio }),
    });
    const dados = (await resposta.json()) as Resultado | RespostaErro;

    if (!resposta.ok || "erro" in dados) {
      definirStatus((dados as RespostaErro).erro ?? `a verificação falhou (${resposta.status})`);
      return;
    }

    ultimo = dados;
    campo.value = dados.dominio;
    desenharResultado(resultado, dados);
    montarAcoes();
    painel.hidden = false;
    definirStatus(null);
    history.replaceState(null, "", `?dominio=${encodeURIComponent(dados.dominio)}`);
    painel.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (falha) {
    definirStatus(`falha na verificação: ${(falha as Error).message}`);
  } finally {
    verificar.disabled = false;
    verificar.textContent = "Verificar";
  }
}

formulario.addEventListener("submit", (evento) => {
  evento.preventDefault();
  const valor = campo.value.trim();
  if (!valor) {
    definirStatus("informe um domínio, por exemplo exemplo.com");
    campo.focus();
    return;
  }
  void verificarDominio(valor);
});

const inicial = new URLSearchParams(location.search).get("dominio");
if (inicial) {
  campo.value = inicial;
  void verificarDominio(inicial);
} else {
  campo.focus();
}

for (const atalho of document.querySelectorAll<HTMLButtonElement>("[data-dominio]")) {
  atalho.addEventListener("click", () => {
    const dominio = atalho.dataset.dominio ?? "";
    campo.value = dominio;
    void verificarDominio(dominio);
  });
}

// Rodapé com a data da última leitura, útil quando a página fica aberta.
const rodape = document.getElementById("rodape") as HTMLElement;
rodape.append(el("span", undefined, `página carregada em ${new Date().toLocaleString("pt-BR")}`));
