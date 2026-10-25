import { test } from "node:test";
import assert from "node:assert/strict";
import { analisarDmarc } from "../nucleo/dmarc.js";
import type { LeitorDns } from "../nucleo/spf.js";

function leitorFixo(mapa: Record<string, string[]>): LeitorDns {
  return {
    txt: async (nome: string) => mapa[nome] ?? [],
    mx: async () => [],
    a: async () => [],
  };
}

const comDmarc = (registro: string) => leitorFixo({ "_dmarc.exemplo.com": [registro] });

test("lê política, relatórios e alinhamento", async () => {
  const dmarc = await analisarDmarc(
    "exemplo.com",
    comDmarc("v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:rel@exemplo.com; adkim=s"),
  );
  assert.equal(dmarc.existe, true);
  assert.equal(dmarc.politica, "reject");
  assert.equal(dmarc.politicaSubdominio, "quarantine");
  assert.equal(dmarc.pct, 100);
  assert.deepEqual(dmarc.rua, ["mailto:rel@exemplo.com"]);
  assert.equal(dmarc.adkim, "s");
});

test("aceita registro escrito sem espaços depois do ponto e vírgula", async () => {
  const dmarc = await analisarDmarc("exemplo.com", comDmarc("v=DMARC1;p=none;rua=mailto:a@b.com"));
  assert.equal(dmarc.politica, "none");
  assert.deepEqual(dmarc.rua, ["mailto:a@b.com"]);
});

test("reclama quando falta a política", async () => {
  const dmarc = await analisarDmarc("exemplo.com", comDmarc("v=DMARC1; rua=mailto:rel@exemplo.com"));
  assert.equal(dmarc.politica, null);
  assert.ok(dmarc.erros.some((e) => e.includes("não informa a política")));
});

test("reclama de política inexistente", async () => {
  const dmarc = await analisarDmarc("exemplo.com", comDmarc("v=DMARC1; p=bloqueia"));
  assert.ok(dmarc.erros.some((e) => e.includes("não existe")));
});

test("reclama de pct fora da faixa", async () => {
  const dmarc = await analisarDmarc("exemplo.com", comDmarc("v=DMARC1; p=none; pct=150"));
  assert.ok(dmarc.erros.some((e) => e.includes("fora da faixa")));
});

test("reclama de endereço de relatório em formato errado", async () => {
  const dmarc = await analisarDmarc("exemplo.com", comDmarc("v=DMARC1; p=none; rua=rel@exemplo.com"));
  assert.ok(dmarc.erros.some((e) => e.includes("mailto")));
});

test("aponta mais de um DMARC publicado", async () => {
  const dmarc = await analisarDmarc(
    "exemplo.com",
    leitorFixo({ "_dmarc.exemplo.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"] }),
  );
  assert.ok(dmarc.erros.some((e) => e.includes("mais de um DMARC")));
});

test("domínio sem DMARC", async () => {
  const dmarc = await analisarDmarc("exemplo.com", leitorFixo({}));
  assert.equal(dmarc.existe, false);
  assert.equal(dmarc.politica, null);
});

test("ignora TXT que não é DMARC", async () => {
  const dmarc = await analisarDmarc("exemplo.com", leitorFixo({ "_dmarc.exemplo.com": ["outra coisa"] }));
  assert.equal(dmarc.existe, false);
});
