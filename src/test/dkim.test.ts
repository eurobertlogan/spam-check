import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { analisarRegistroDkim, bitsDaChave } from "../nucleo/dkim.js";

function chavePublica(bits: number): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

test("lê o tamanho de uma chave de 2048 bits", () => {
  assert.equal(bitsDaChave(chavePublica(2048)), 2048);
});

test("lê o tamanho de uma chave de 1024 bits", () => {
  assert.equal(bitsDaChave(chavePublica(1024)), 1024);
});

test("devolve nulo quando o conteúdo não é uma chave", () => {
  assert.equal(bitsDaChave("nao-e-chave"), null);
});

test("registro normal de DKIM", () => {
  const resultado = analisarRegistroDkim("google", [`v=DKIM1; k=rsa; p=${chavePublica(2048)}`]);
  assert.equal(resultado.publicado, true);
  assert.equal(resultado.bits, 2048);
  assert.equal(resultado.problema, null);
});

test("chave revogada, com p vazio", () => {
  const resultado = analisarRegistroDkim("default", ["v=DKIM1; p="]);
  assert.equal(resultado.publicado, true);
  assert.equal(resultado.revogada, true);
  assert.ok(resultado.problema?.includes("revogada"));
});

test("chave curta demais vira problema", () => {
  const resultado = analisarRegistroDkim("s1", [`v=DKIM1; p=${chavePublica(512)}`]);
  assert.equal(resultado.revogada, false);
  assert.ok(resultado.problema?.includes("curta demais"));
});

test("seletor sem registro não é publicado", () => {
  const resultado = analisarRegistroDkim("mail", []);
  assert.equal(resultado.publicado, false);
  assert.equal(resultado.problema, null);
});

test("ignora TXT que não é de DKIM", () => {
  const resultado = analisarRegistroDkim("mail", ["google-site-verification=abc123"]);
  assert.equal(resultado.publicado, false);
});
