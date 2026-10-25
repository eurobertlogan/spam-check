import { test } from "node:test";
import assert from "node:assert/strict";
import { avaliar, type EntradaAvaliacao } from "../nucleo/avaliar.js";
import type { AnaliseSpf } from "../nucleo/spf.js";
import type { AnaliseDmarc } from "../nucleo/dmarc.js";
import type { AnaliseReputacao } from "../nucleo/reputacao.js";

const spfVazio = (extra: Partial<AnaliseSpf> = {}): AnaliseSpf => ({
  registros: [],
  mecanismos: [],
  qualificadorAll: null,
  consultas: 0,
  voidLookups: 0,
  cadeia: [],
  redireciona: false,
  erros: [],
  avisos: [],
  ...extra,
});

const dmarcAusente: AnaliseDmarc = {
  registros: [],
  existe: false,
  bruto: null,
  politica: null,
  politicaSubdominio: null,
  pct: null,
  rua: [],
  ruf: [],
  aspf: null,
  adkim: null,
  erros: [],
  avisos: [],
};

const reputacaoVazia: AnaliseReputacao = { servidores: [], semIp: [] };

function entrada(extra: Partial<EntradaAvaliacao> = {}): EntradaAvaliacao {
  return {
    dominio: "exemplo.com",
    mx: [],
    spf: spfVazio(),
    dkim: { publicados: [], tentados: [], curinga: false },
    dmarc: dmarcAusente,
    reputacao: reputacaoVazia,
    enderecosDoDominio: [],
    ...extra,
  };
}

const tem = (achados: { nivel: string; mensagem: string }[], nivel: string, trecho: string): boolean =>
  achados.some((a) => a.nivel === nivel && a.mensagem.includes(trecho));

test("domínio sem SPF recebe um erro só, não dois", () => {
  // A análise do SPF também devolve "não tem registro SPF", e essa mensagem não
  // pode aparecer junto com a regra que já traz a correção.
  const { achados } = avaliar(entrada({ spf: spfVazio({ erros: ["exemplo.com não tem registro SPF"] }) }));
  const errosDeSpf = achados.filter((a) => a.area === "SPF" && a.nivel === "erro");
  assert.equal(errosDeSpf.length, 1);
  assert.ok(errosDeSpf[0]?.mensagem.includes("não existe SPF"));
});

test("sem SPF, sem DMARC e sem DKIM a nota desaba", () => {
  const { achados, nota } = avaliar(entrada());
  assert.ok(tem(achados, "erro", "não existe SPF"));
  assert.ok(tem(achados, "erro", "não existe DMARC"));
  assert.ok(nota < 4);
});

test("MX nulo não é tratado como erro", () => {
  const { achados } = avaliar(entrada({ mx: [{ prioridade: 0, host: "." }] }));
  assert.ok(tem(achados, "info", "MX nulo"));
  assert.equal(tem(achados, "erro", "não tem registro MX"), false);
});

test("SPF com +all é erro", () => {
  const { achados } = avaliar(
    entrada({ spf: spfVazio({ registros: ["v=spf1 +all"], qualificadorAll: "+" }) }),
  );
  assert.ok(tem(achados, "erro", "+all libera qualquer servidor"));
});

test("SPF com ~all é aviso", () => {
  const { achados } = avaliar(
    entrada({ spf: spfVazio({ registros: ["v=spf1 ~all"], qualificadorAll: "~" }) }),
  );
  assert.ok(tem(achados, "aviso", "~all marca a mensagem como suspeita"));
});

test("redirect não cobra o all ausente", () => {
  const { achados } = avaliar(
    entrada({ spf: spfVazio({ registros: ["v=spf1 redirect=_spf.exemplo.com"], redireciona: true }) }),
  );
  assert.ok(tem(achados, "ok", "delega a decisão"));
  assert.equal(tem(achados, "aviso", "não termina em all"), false);
});

test("curinga de DKIM não vira erro por seletor", () => {
  const { achados } = avaliar(
    entrada({ dkim: { publicados: [], tentados: ["default"], curinga: true } }),
  );
  assert.ok(tem(achados, "info", "curinga"));
  assert.equal(tem(achados, "erro", "revogada"), false);
});

test("chave DKIM revogada é erro", () => {
  const { achados } = avaliar(
    entrada({
      dkim: {
        publicados: [{ seletor: "s1", publicado: true, bruto: "v=DKIM1; p=", bits: null, revogada: true, problema: "a chave está revogada, com p= vazio, então ela não assina nada" }],
        tentados: ["s1"],
        curinga: false,
      },
    }),
  );
  assert.ok(tem(achados, "erro", "revogada"));
});

test("p=none recebe aviso e p=reject recebe ok", () => {
  const comNone = avaliar(
    entrada({ dmarc: { ...dmarcAusente, existe: true, politica: "none", bruto: "v=DMARC1; p=none" } }),
  );
  assert.ok(tem(comNone.achados, "aviso", "p=none apenas observa"));

  const comReject = avaliar(
    entrada({ dmarc: { ...dmarcAusente, existe: true, politica: "reject", bruto: "v=DMARC1; p=reject" } }),
  );
  assert.ok(tem(comReject.achados, "ok", "p=reject"));
});

test("IP em lista de bloqueio é erro com o nome da lista", () => {
  const { achados } = avaliar(
    entrada({
      mx: [{ prioridade: 10, host: "mx.exemplo.com" }],
      reputacao: {
        semIp: [],
        servidores: [
          {
            host: "mx.exemplo.com",
            prioridade: 10,
            ips: [
              {
                ip: "203.0.113.10",
                reverso: "mx.exemplo.com",
                listagens: [{ zona: "zen.spamhaus.org", nome: "Spamhaus ZEN", codigo: "127.0.0.3", significado: "listado por enviar spam diretamente" }],
                listasConsultadas: 4,
                listasIndisponiveis: [],
              },
            ],
          },
        ],
      },
    }),
  );
  assert.ok(tem(achados, "erro", "Spamhaus ZEN"));
});

test("relatório enxuto: um aviso para todos os reversos ausentes", () => {
  const ips = [1, 2, 3, 4, 5].map((numero) => ({
    ip: `203.0.113.${numero}`,
    reverso: null,
    listagens: [],
    listasConsultadas: 4,
    listasIndisponiveis: [],
  }));

  const { achados } = avaliar(
    entrada({
      mx: [{ prioridade: 10, host: "mx.exemplo.com" }],
      reputacao: { semIp: [], servidores: [{ host: "mx.exemplo.com", prioridade: 10, ips }] },
    }),
  );

  const avisosDeReverso = achados.filter((a) => a.mensagem.includes("sem nome reverso"));
  assert.equal(avisosDeReverso.length, 1);
  assert.ok(avisosDeReverso[0]?.mensagem.includes("5 endereço(s)"));
});
