/**
 * Análise do DKIM.
 *
 * O DKIM não tem um lugar único para procurar: cada remetente escolhe um nome de
 * seletor e publica a chave pública em <seletor>._domainkey.<domínio>. Como não
 * existe lista oficial, o caminho honesto é tentar os seletores que os provedores
 * usam de verdade e dizer exatamente o que faltou.
 */

export const SELETORES_COMUNS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "k2",
  "mail",
  "dkim",
  "smtp",
  "amazonses",
  "mandrill",
  "sendgrid",
  "mailjet",
  "zoho",
  "protonmail",
  "cm",
  "em",
];

/**
 * Nome de seletor que ninguém publicaria de verdade. Serve para descobrir se o
 * domínio responde a qualquer seletor com um registro vazio, que é o curinga
 * usado de propósito para impedir que se descubra qual seletor é o real.
 */
export const SELETOR_SONDA = "sonda-spam-check-8f2a";

export interface ResultadoDkim {
  seletor: string;
  publicado: boolean;
  bruto: string | null;
  bits: number | null;
  revogada: boolean;
  problema: string | null;
}

/** Lê os bytes da chave pública e estima o tamanho do módulo RSA. */
export function bitsDaChave(base64: string): number | null {
  let bytes: Buffer;
  try {
    bytes = Buffer.from(base64.replace(/\s+/g, ""), "base64");
  } catch {
    return null;
  }
  if (bytes.length < 40) return null;

  // A chave vem em DER, começando por SEQUENCE. Dentro dela interessa o BIT
  // STRING, que guarda o módulo do RSA como primeiro INTEGER.
  try {
    let pos = 0;
    const comprimento = (): number => {
      const primeiro = bytes[pos++] ?? 0;
      if (primeiro < 0x80) return primeiro;
      const quantos = primeiro & 0x7f;
      let total = 0;
      for (let i = 0; i < quantos; i++) total = (total << 8) | (bytes[pos++] ?? 0);
      return total;
    };

    if (bytes[pos++] !== 0x30) return null;
    comprimento();

    // SEQUENCE da assinatura (algoritmo): pula.
    if (bytes[pos] === 0x30) {
      pos++;
      const tamanho = comprimento();
      pos += tamanho;
    }

    if (bytes[pos++] !== 0x03) return null;
    comprimento();
    pos++; // byte de bits não usados

    if (bytes[pos++] !== 0x30) return null;
    comprimento();

    if (bytes[pos++] !== 0x02) return null;
    const tamanhoModulo = comprimento();
    const inicio = pos;
    let significativos = tamanhoModulo;
    if (bytes[inicio] === 0x00) {
      significativos--;
      pos++;
    }
    const primeiro = bytes[pos] ?? 0;
    if (primeiro === 0) return null;
    const bitsDoPrimeiro = 32 - Math.clz32(primeiro);
    return (significativos - 1) * 8 + bitsDoPrimeiro;
  } catch {
    return null;
  }
}

export function analisarRegistroDkim(seletor: string, registros: string[]): ResultadoDkim {
  const dkim = registros.map((r) => r.trim()).find((r) => /v=dkim1/i.test(r) || /p=/.test(r));

  if (!dkim) {
    return { seletor, publicado: false, bruto: null, bits: null, revogada: false, problema: null };
  }

  const chave = /(?:^|;)\s*p\s*=\s*([^;]*)/i.exec(dkim)?.[1]?.trim() ?? "";
  const revogada = chave === "";
  const bits = revogada ? null : bitsDaChave(chave);
  const tipo = /(?:^|;)\s*k\s*=\s*([^;]+)/i.exec(dkim)?.[1]?.trim().toLowerCase() ?? "rsa";

  let problema: string | null = null;
  if (revogada) problema = "a chave está revogada, com p= vazio, então ela não assina nada";
  else if (tipo !== "rsa") problema = null;
  else if (bits === null) problema = "não consegui ler o tamanho da chave publicada";
  else if (bits < 1024) problema = `chave de ${bits} bits, curta demais para os padrões atuais`;

  return { seletor, publicado: true, bruto: dkim, bits, revogada, problema };
}

export async function analisarDkim(
  dominio: string,
  seletores: string[],
  txt: (nome: string) => Promise<string[]>,
): Promise<{ publicados: ResultadoDkim[]; tentados: string[] }> {
  const encontrados: ResultadoDkim[] = [];

  const respostas = await Promise.all(
    seletores.map(async (seletor) => {
      const registros = await txt(`${seletor}._domainkey.${dominio}`);
      return analisarRegistroDkim(seletor, registros);
    }),
  );

  for (const resposta of respostas) {
    if (resposta.publicado) encontrados.push(resposta);
  }

  return { publicados: encontrados, tentados: seletores };
}
