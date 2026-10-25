/**
 * Transforma o que foi encontrado no DNS em uma lista de achados com prioridade.
 *
 * A ordem importa: primeiro o que impede a entrega, depois o que degrada, e por
 * último o que já está certo. É a diferença entre um relatório que a pessoa lê e
 * um despejo de registros.
 */
import type { Achado, Nivel } from "./tipos.js";
import type { AnaliseSpf } from "./spf.js";
import type { AnaliseDmarc } from "./dmarc.js";
import type { AnaliseReputacao } from "./reputacao.js";
import type { ResultadoDkim } from "./dkim.js";
import type { ServidorMx } from "./dns.js";

export interface EntradaAvaliacao {
  dominio: string;
  mx: ServidorMx[];
  spf: AnaliseSpf;
  dkim: { publicados: ResultadoDkim[]; tentados: string[]; curinga: boolean };
  dmarc: AnaliseDmarc;
  reputacao: AnaliseReputacao;
  enderecosDoDominio: string[];
}

const juntar = (valores: string[]): string => valores.join(", ");

export function avaliar(entrada: EntradaAvaliacao): { achados: Achado[]; nota: number; veredito: string } {
  const achados: Achado[] = [];
  const registrar = (area: string, nivel: Nivel, mensagem: string, correcao?: string): void => {
    achados.push(correcao ? { area, nivel, mensagem, correcao } : { area, nivel, mensagem });
  };

  // ---------- MX ----------
  const mxNulo = entrada.mx.length > 0 && entrada.mx.every((m) => !m.host || m.host === ".");

  if (mxNulo) {
    registrar(
      "MX",
      "info",
      `${entrada.dominio} publica um MX nulo (0 .), que é a forma padrão de declarar que este domínio não recebe email`,
    );
  } else if (entrada.mx.length === 0) {
    registrar(
      "MX",
      "erro",
      `${entrada.dominio} não tem registro MX, então não recebe nenhuma mensagem`,
      "publique um MX apontando para o provedor de email, por exemplo mail.exemplo.com com prioridade 10",
    );
  } else {
    registrar("MX", "ok", `${entrada.mx.length} servidor(es) de entrada: ${juntar(entrada.mx.map((m) => m.host))}`);
    if (entrada.reputacao.semIp.length > 0) {
      registrar(
        "MX",
        "erro",
        `o MX ${juntar(entrada.reputacao.semIp)} não resolve para nenhum endereço`,
        "confira se o nome está certo e se o DNS desse subdomínio existe",
      );
    }
  }

  if (entrada.enderecosDoDominio.length > 0) {
    registrar("Domínio", "ok", `o domínio resolve para ${juntar(entrada.enderecosDoDominio)}`);
  } else if (entrada.mx.length > 0) {
    registrar(
      "Domínio",
      "info",
      "o domínio não tem registro A, o que é normal quando ele só recebe e envia email",
    );
  }

  // ---------- SPF ----------
  if (entrada.spf.registros.length === 0) {
    registrar(
      "SPF",
      "erro",
      `não existe SPF em ${entrada.dominio}, então qualquer servidor do mundo pode enviar email se passando por você`,
      `publique um TXT em @ com o valor: v=spf1 include:_spf.do-seu-provedor.com ~all`,
    );
  } else {
    registrar("SPF", "ok", `SPF publicado: ${entrada.spf.registros[0] ?? ""}`);

    const all = entrada.spf.qualificadorAll;
    if (all === "-") {
      registrar("SPF", "ok", "-all no fim: só os servidores listados podem enviar em nome do domínio");
    } else if (all === "+" || all === "") {
      registrar(
        "SPF",
        "erro",
        "+all libera qualquer servidor do mundo a enviar pelo seu domínio, e isso é um convite ao roubo de identidade",
        "troque por -all depois de conferir se todos os seus remetentes estão listados",
      );
    } else if (all === "~") {
      registrar(
        "SPF",
        "aviso",
        "~all marca a mensagem como suspeita em vez de rejeitar, então quem falsifica ainda tem chance",
        "depois de acompanhar alguns dias de relatório, troque para -all",
      );
    } else if (all === "?") {
      registrar("SPF", "aviso", "?all não afirma nada, então o SPF praticamente não faz efeito");
    } else if (all === null) {
      if (entrada.spf.redireciona) {
        registrar("SPF", "ok", "o SPF delega a decisão para outro domínio via redirect, que é uma forma válida de organizar");
      } else {
        registrar(
          "SPF",
          "aviso",
          "o SPF não termina em all, então o resultado padrão é neutro e quem recebe decide sozinho",
          "termine o registro com -all",
        );
      }
    }

    if (entrada.spf.consultas > 10) {
      registrar(
        "SPF",
        "erro",
        `o SPF gasta ${entrada.spf.consultas} consultas DNS e o limite é 10, então quem passa do limite recebe falha permanente`,
        "junte includes repetidos ou aponte para um SPF único do seu provedor, sem empilhar domínios",
      );
    } else if (entrada.spf.consultas > 8) {
      registrar(
        "SPF",
        "aviso",
        `o SPF já usa ${entrada.spf.consultas} das 10 consultas permitidas, sem margem para crescer`,
      );
    } else {
      registrar("SPF", "ok", `${entrada.spf.consultas} consulta(s) DNS, dentro do limite de 10`);
    }
  }

  // A ausência de SPF já foi dita acima com a correção junto, então os erros da
  // análise só entram em cena quando existe registro para analisar.
  if (entrada.spf.registros.length > 0) {
    for (const erro of entrada.spf.erros) {
      if (!achados.some((a) => a.mensagem === erro)) registrar("SPF", "erro", erro);
    }
    for (const aviso of entrada.spf.avisos) {
      if (!achados.some((a) => a.mensagem === aviso)) registrar("SPF", "aviso", aviso);
    }
  }

  // ---------- DKIM ----------
  if (entrada.dkim.curinga) {
    registrar(
      "DKIM",
      "info",
      "o domínio responde a qualquer seletor com um registro vazio (v=DKIM1; p=), que é um curinga publicado de propósito para impedir que se descubra qual seletor é o verdadeiro",
    );
    registrar(
      "DKIM",
      "aviso",
      "não dá para confirmar a chave pelo DNS daqui: confira no painel do provedor qual seletor você publicou e rode de novo com --seletores nome-do-seletor",
    );
  } else if (entrada.dkim.publicados.length === 0) {
    registrar(
      "DKIM",
      "aviso",
      `não achei chave DKIM nos ${entrada.dkim.tentados.length} seletores comuns`,
      "se você assina com um seletor próprio, informe com --seletores nome1,nome2 e rode de novo",
    );
  } else {
    for (const chave of entrada.dkim.publicados) {
      if (chave.revogada || chave.problema) {
        registrar(
          "DKIM",
          chave.revogada ? "erro" : "aviso",
          `seletor "${chave.seletor}": ${chave.problema}`,
          "publique a chave novamente no painel do provedor e copie o valor para o DNS",
        );
      } else {
        registrar(
          "DKIM",
          "ok",
          `seletor "${chave.seletor}" publicado${chave.bits ? ` com chave de ${chave.bits} bits` : ""}`,
        );
      }
    }
    if (entrada.dkim.publicados.length > 1) {
      registrar(
        "DKIM",
        "info",
        `${entrada.dkim.publicados.length} seletores publicados: normalmente significa rotação de chave em andamento`,
      );
    }
  }

  // ---------- DMARC ----------
  if (!entrada.dmarc.existe) {
    registrar(
      "DMARC",
      "erro",
      "não existe DMARC, então quem recebe decide sozinho o que fazer com quem falsifica o seu domínio",
      "publique um TXT em _dmarc com: v=DMARC1; p=none; rua=mailto:dmarc@seu-dominio.com, acompanhe os relatórios por duas semanas e depois suba para quarantine e reject",
    );
  } else {
    const politica = entrada.dmarc.politica;
    const bruto = entrada.dmarc.bruto ?? "";

    if (politica === "none") {
      registrar(
        "DMARC",
        "aviso",
        "p=none apenas observa: nada acontece com quem falsifica o domínio",
        "observe os relatórios por duas semanas e mude para p=quarantine, depois p=reject",
      );
    } else if (politica === "quarantine") {
      registrar("DMARC", "ok", "p=quarantine: mensagem falsificada vai para o spam");
    } else if (politica === "reject") {
      registrar("DMARC", "ok", "p=reject: mensagem falsificada é recusada na porta");
    }

    registrar("DMARC", "ok", `DMARC publicado: ${bruto}`);

    if (entrada.dmarc.pct !== null && entrada.dmarc.pct < 100) {
      registrar(
        "DMARC",
        "aviso",
        `pct=${entrada.dmarc.pct} aplica a política só em parte das mensagens`,
        "com os remetentes já conferidos, deixe em 100",
      );
    }
    if (entrada.dmarc.rua.length === 0) {
      registrar(
        "DMARC",
        "aviso",
        "sem rua, você não recebe relatório e não fica sabendo quem tenta enviar em nome do domínio",
        "acrescente rua=mailto:dmarc@seu-dominio.com",
      );
    } else {
      registrar("DMARC", "ok", `relatórios vão para ${juntar(entrada.dmarc.rua)}`);
    }
    if (entrada.dmarc.aspf === "s" || entrada.dmarc.adkim === "s") {
      registrar(
        "DMARC",
        "aviso",
        "o alinhamento está em modo estrito, então pequenas diferenças de subdomínio já reprovam a mensagem",
        "confirme se é intencional antes de manter",
      );
    }
  }

  for (const erro of entrada.dmarc.erros) {
    if (!achados.some((a) => a.mensagem === erro)) registrar("DMARC", "erro", erro);
  }

  // ---------- Reputação ----------
  // Um resumo por assunto, não uma linha por servidor: cinco MX renderiam dez
  // linhas quase iguais, e relatório que ninguém lê não serve para nada. Cada IP
  // listado ganha linha própria, porque aí a ação é específica.
  const todos = entrada.reputacao.servidores.flatMap((servidor) =>
    servidor.ips.map((ip) => ({ host: servidor.host, ...ip })),
  );
  const listados = todos.filter((ip) => ip.listagens.length > 0);
  const semReverso = todos.filter((ip) => !ip.reverso);
  const indisponiveis = [...new Set(todos.flatMap((ip) => ip.listasIndisponiveis))];
  const quantasListas = todos[0]?.listasConsultadas ?? 0;

  for (const ip of listados) {
    const listas = ip.listagens.map((l) => `${l.nome} (${l.significado})`).join("; ");
    registrar(
      "Reputação",
      "erro",
      `o IP ${ip.ip} do MX ${ip.host} está em lista de bloqueio: ${listas}`,
      "peça a remoção na lista citada e verifique se o servidor não está sendo usado para enviar spam",
    );
  }

  if (todos.length > 0 && listados.length === 0) {
    registrar(
      "Reputação",
      "ok",
      `${todos.length} endereço(s) de ${entrada.reputacao.servidores.length} servidor(es) de entrada: nenhum aparece nas ${quantasListas} listas de bloqueio consultadas`,
    );
  }

  if (semReverso.length > 0) {
    registrar(
      "Reputação",
      "aviso",
      `${semReverso.length} endereço(s) sem nome reverso utilizável: ${semReverso.map((ip) => ip.ip).join(", ")}. Boa parte dos servidores recusa quem não tem PTR`,
      "peça ao seu provedor para apontar o reverso de cada endereço para o nome do servidor",
    );
  } else if (todos.length > 0) {
    registrar("Reputação", "ok", "todos os endereços verificados têm nome reverso");
  }

  if (indisponiveis.length > 0) {
    registrar(
      "Reputação",
      "info",
      `não consegui consultar ${juntar(indisponiveis)}: o resultado dessas listas ficou em branco`,
    );
  }

  // ---------- Nota ----------
  const erros = achados.filter((a) => a.nivel === "erro").length;
  const avisos = achados.filter((a) => a.nivel === "aviso").length;
  const nota = Math.max(0, Math.round((10 - erros * 2 - avisos * 0.5) * 10) / 10);

  const veredito =
    nota >= 9
      ? "configuração pronta: nada aqui explica cair no spam"
      : nota >= 7
        ? "configuração razoável, com pontos a ajustar"
        : nota >= 4
          ? "há falhas que explicam parte dos emails cair no spam"
          : "a configuração atual derruba o envio antes de qualquer análise de conteúdo";

  return { achados, nota, veredito };
}
