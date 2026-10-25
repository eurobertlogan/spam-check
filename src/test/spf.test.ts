import { test } from "node:test";
import assert from "node:assert/strict";
import { analisarSpf, extrairSpf, LIMITE_CONSULTAS } from "../nucleo/spf.js";
import type { LeitorDns } from "../nucleo/spf.js";

/** Leitor de mentira: responde exatamente o que o teste precisa. */
function leitorFixo(mapa: Record<string, string[]>): LeitorDns {
  return {
    txt: async (nome: string) => mapa[nome] ?? [],
    mx: async (nome: string) => (mapa[`mx:${nome}`] ?? []).map((host, i) => ({ prioridade: i, host })),
    a: async (nome: string) => mapa[`a:${nome}`] ?? [],
  };
}

test("reconhece apenas registros que começam com v=spf1", () => {
  const registros = ["v=spf1 -all", "google-site-verification=abc", " v=SPF1 include:x.com ~all ", "v=spf1x"];
  assert.deepEqual(extrairSpf(registros), ["v=spf1 -all", "v=SPF1 include:x.com ~all"]);
});

test("lê o qualificador do all", async () => {
  const spf = await analisarSpf("exemplo.com", leitorFixo({ "exemplo.com": ["v=spf1 ip4:203.0.113.0/24 -all"] }));
  assert.equal(spf.qualificadorAll, "-");
  assert.equal(spf.erros.length, 0);
});

test("avisa quando o all é permissivo demais", async () => {
  const mais = await analisarSpf("exemplo.com", leitorFixo({ "exemplo.com": ["v=spf1 +all"] }));
  assert.equal(mais.qualificadorAll, "+");
});

test("aponta dois registros SPF no mesmo domínio", async () => {
  const spf = await analisarSpf(
    "exemplo.com",
    leitorFixo({ "exemplo.com": ["v=spf1 include:a.com -all", "v=spf1 include:b.com -all"] }),
  );
  assert.ok(spf.erros.some((e) => e.includes("mais de um registro SPF")));
});

test("segue include e soma as consultas da cadeia", async () => {
  const spf = await analisarSpf(
    "exemplo.com",
    leitorFixo({
      "exemplo.com": ["v=spf1 include:_spf.exemplo.com -all"],
      "_spf.exemplo.com": ["v=spf1 include:_net.exemplo.com ip4:198.51.100.0/24 ~all"],
      "_net.exemplo.com": ["v=spf1 ip4:192.0.2.0/24 -all"],
    }),
  );
  assert.equal(spf.consultas, 2);
  assert.equal(spf.qualificadorAll, "-");
  assert.equal(spf.cadeia.length, 3);
});

test("conta include que não leva a lugar nenhum como consulta vazia", async () => {
  const spf = await analisarSpf(
    "exemplo.com",
    leitorFixo({
      "exemplo.com": ["v=spf1 include:sumiu.com include:tambem.com include:foi.com -all"],
    }),
  );
  assert.equal(spf.voidLookups, 3);
  assert.ok(spf.erros.some((e) => e.includes("não devolvem nada")));
});

test("avisa quando passa do limite de consultas", async () => {
  const mapa: Record<string, string[]> = {
    "exemplo.com": ["v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:x${i}.com`).join(" ") + " -all"],
  };
  for (let i = 0; i < 11; i++) mapa[`x${i}.com`] = ["v=spf1 -all"];

  const spf = await analisarSpf("exemplo.com", leitorFixo(mapa));
  assert.equal(spf.consultas, 11);
  assert.ok(spf.erros.some((e) => e.includes(`limite é ${LIMITE_CONSULTAS}`)));
});

test("trata redirect como delegação válida e acompanha o alvo", async () => {
  const spf = await analisarSpf(
    "exemplo.com",
    leitorFixo({
      "exemplo.com": ["v=spf1 redirect=_spf.exemplo.com"],
      "_spf.exemplo.com": ["v=spf1 ip4:198.51.100.0/24 -all"],
    }),
  );
  assert.equal(spf.redireciona, true);
  assert.equal(spf.qualificadorAll, "-");
  assert.equal(spf.consultas, 1);
  assert.equal(spf.erros.length, 0);
});

test("reclama de termos que nunca serão avaliados depois do all", async () => {
  const spf = await analisarSpf(
    "exemplo.com",
    leitorFixo({ "exemplo.com": ["v=spf1 -all include:tarde.com"] }),
  );
  assert.ok(spf.avisos.some((a) => a.includes("depois do all")));
});

test("não entende termo inventado", async () => {
  const spf = await analisarSpf("exemplo.com", leitorFixo({ "exemplo.com": ["v=spf1 manda-tudo -all"] }));
  assert.ok(spf.erros.some((e) => e.includes("não entendi o termo")));
});

test("avisa sobre o mecanismo ptr", async () => {
  const spf = await analisarSpf("exemplo.com", leitorFixo({ "exemplo.com": ["v=spf1 ptr -all"] }));
  assert.ok(spf.avisos.some((a) => a.includes("ptr")));
});

test("domínio sem SPF nenhum", async () => {
  const spf = await analisarSpf("exemplo.com", leitorFixo({}));
  assert.equal(spf.registros.length, 0);
  assert.ok(spf.erros[0]?.includes("não tem registro SPF"));
});
