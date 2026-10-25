# spam-check

Uma página local que responde por que o seu email cai no spam. Digite o domínio, clique em verificar e leia o diagnóstico montado só com o DNS público. Sem cadastro, sem painel e sem enviar email nenhum para lugar algum.

```bash
git clone https://github.com/eurobertlogan/spam-check.git
cd spam-check
npm install
npm start
```

Abre em http://localhost:4331. As mesmas verificações também rodam na linha de comando, para CI.

## O que ele confere

| área | o que ele lê |
|---|---|
| MX | os servidores que recebem o seu email e se eles resolvem |
| SPF | o registro publicado, o `all` final, cada `include:` seguido até o fim e quantas das 10 consultas permitidas você gasta |
| DKIM | 19 nomes de seletor comuns, a chave pública, o tamanho dela e chaves deixadas revogadas com `p=` vazio |
| DMARC | política, política de subdomínio, percentual, endereços de relatório e modo de alinhamento |
| Reputação | os IPs dos seus servidores de entrada em quatro listas de bloqueio, mais o nome reverso de cada um |

Cada linha é um de quatro níveis. **erro** significa que a entrega quebra, **aviso** significa que ela piora, **ok** confirma o que está certo e **info** explica algo que parece errado e não é. A nota vai de 0 a 10, seguida de uma frase dizendo o que aquela configuração significa na prática.

## Exportar

A página tem um botão que salva um arquivo único com o diagnóstico inteiro, pronto para mandar para quem cuida da zona DNS. Tem também um botão que copia o JSON cru, e a barra de endereço guarda o domínio, então um link para a página abre com o mesmo diagnóstico.

## Linha de comando

```bash
npm run checar -- exemplo.com
npm run checar -- exemplo.com --json
```

Sai com código 1 quando existe algum erro, então serve de porteiro em CI:

```
MX        ok    2 servidor(es) de entrada: mx1.exemplo.com, mx2.exemplo.com
SPF       erro  o SPF gasta 12 consultas DNS e o limite é 10
                 correção: junte includes repetidos ou aponte para um SPF único do provedor
DKIM      ok    seletor "google" publicado com chave de 2048 bits
DMARC     aviso p=none apenas observa: nada acontece com quem falsifica o domínio
Reputação ok    3 endereço(s) de 2 servidor(es) de entrada: nenhum aparece nas 4 listas

nota 7.5 de 10 configuração razoável, com pontos a ajustar
42 consultas DNS em 610 ms
```

Opções da linha de comando:

```
--json                   imprime o resultado cru
--seletores a,b,c        seletores de DKIM a testar, além dos comuns
--resolvedor <ip>        servidor DNS a usar, pode repetir
--limite <ms>            tempo máximo por consulta (padrão 6000)
--sem-cor                saída sem cor
```

A página aceita `--porta` e `--host`:

```bash
npm start -- --porta 5000
```

## Requisitos

Node 18 ou mais novo. Sem dependência de execução: `typescript` e `@types/node` existem só para compilar.

## O que ele não faz

Ele lê DNS, e DNS é parte da história. Não abre o seu email, não conversa com a plataforma de envio e não enxerga a reputação do domínio, a idade dele, o conteúdo da mensagem nem quantas pessoas marcaram você como spam. Também não consegue confirmar o DKIM quando o domínio publica um registro curinga que responde a qualquer seletor com uma chave vazia, que é exatamente o truque usado para impedir a descoberta do seletor: nesse caso o comando avisa e pede `--seletores`.

Algumas listas de bloqueio recusam consultas que vêm de resolvedores públicos. Quando isso acontece, o relatório diz que a lista não pôde ser consultada em vez de fingir que o IP está limpo. Depois de corrigir os registros, a melhora não é imediata: listas e provedores guardam histórico, e a nota não muda no mesmo dia.

## Quando o DNS está certo e o email continua caindo no spam

Confira, nesta ordem: o domínio do cabeçalho `From` é o mesmo que tem SPF e DKIM alinhados, a plataforma de envio está no SPF desse domínio exato e não só de um subdomínio, a mensagem tem texto de verdade e um link que resolve, o domínio já envia há mais de alguns dias e o `Reply-To` aponta para uma caixa que aceita resposta.

## Estrutura

```
src/nucleo/       as regras: SPF, DKIM, DMARC, reputação, nota. Não sabem que existe uma página
src/servidor/     servidor HTTP, a API e a linha de comando
src/navegador/    os componentes da página, tipados para o navegador
public/           a casca: um campo, um botão, os resultados
src/test/         39 testes com respostas de DNS fixas, sem rede
```

TypeScript do começo ao fim, com duas configurações separadas: o servidor compila com os tipos do Node e o navegador com os tipos do DOM, então nenhum lado enxerga o outro por engano. O núcleo é puro o bastante para ser testado com respostas fixas, e é por isso que os testes nunca tocam na rede.

## Autor

[robertlogan.cc](https://robertlogan.cc)

## Licença

MIT
