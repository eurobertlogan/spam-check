# spam-check

A local page that answers why your email goes to spam. Type the domain, press verify, and read the diagnosis built from public DNS alone. No sign up, no dashboard, and no email sent anywhere.

```bash
git clone https://github.com/eurobertlogan/spam-check.git
cd spam-check
npm install
npm start
```

It opens on http://localhost:4331. The same checks also run from the command line, for CI.

## What it checks

| area | what it reads |
|---|---|
| MX | the servers that receive your mail, and whether they resolve |
| SPF | the published record, the final `all`, every `include:` followed to the end, and how many of the 10 allowed lookups you are spending |
| DKIM | 19 common selector names, the public key, its size, and keys left revoked with an empty `p=` |
| DMARC | policy, subdomain policy, percentage, report addresses, alignment mode |
| Reputation | the IPs of your inbound servers in four blocklists, plus the reverse name of each one |

Each line is one of four levels. **erro** means delivery breaks, **aviso** means it is degraded, **ok** confirms what is right, and **info** explains something that looks wrong and is not. The score runs from 0 to 10, followed by a sentence saying what that configuration means in practice.

## Exporting

The page has a button that saves a single self contained file with the whole diagnosis, ready to send to whoever holds the DNS zone. There is also a button that copies the raw JSON, and the address bar keeps the domain, so a link to the page opens with the same diagnosis.

## Command line

```bash
npm run checar -- exemplo.com
npm run checar -- exemplo.com --json
```

Exits with code 1 when there is any error, so it works as a gate in CI:

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

Command line options:

```
--json                   print the raw result
--seletores a,b,c        DKIM selectors to test, on top of the common ones
--resolvedor <ip>        DNS server to use, repeatable
--limite <ms>            timeout per query (default 6000)
--sem-cor                output without colour
```

The page takes `--porta` and `--host`:

```bash
npm start -- --porta 5000
```

## Requirements

Node 18 or newer. No runtime dependency: `typescript` and `@types/node` exist only to build.

## What it does not do

It reads DNS, and DNS is only part of the story. It does not open your email, does not talk to the sending platform, and cannot see domain reputation, domain age, the content of the message, or how many people marked you as spam. It also cannot confirm DKIM when the domain publishes a wildcard record that answers every selector with an empty key, which is exactly the trick used to stop selector enumeration: in that case the tool says so and asks for `--seletores`.

Some blocklists refuse queries coming through public resolvers. When that happens the report says the list could not be checked instead of pretending the IP is clean. After fixing the records, improvement is not immediate: blocklists and providers keep history, and the score will not move on the same day.

## When the DNS is right and the email still goes to spam

Check, in this order: the domain in the `From` header is the one with SPF and DKIM aligned, the sending platform is in the SPF of that exact domain and not only of a subdomain, the message has real text and a link that resolves, the domain has been sending for more than a few days, and the `Reply-To` points to a mailbox that accepts replies.

## Structure

```
src/nucleo/       the rules: SPF, DKIM, DMARC, reputation, score. No idea a page exists
src/servidor/     HTTP server, the API, and the command line
src/navegador/    the page components, typed for the browser
public/           the shell: one field, one button, the results
src/test/         39 tests with fixed DNS answers, no network
```

TypeScript throughout, with two separate configurations: the server compiles with Node types, the browser compiles with DOM types, so neither side sees the other by accident. The core is pure enough to be tested with fixed answers, which is why the tests never touch the network.

## Em português

Você abre a página, digita o domínio e vê por que o email cai no spam: MX, SPF, DKIM, DMARC, listas de bloqueio e reverso. A nota vai de 0 a 10 e cada linha é erro, aviso, ok ou info, sempre com o que fazer quando algo está errado. Dá para exportar a página do diagnóstico e mandar para quem cuida da zona DNS, e o mesmo comando roda no terminal para usar em CI. Leia também o [README.pt-BR.md](README.pt-BR.md).

## Author

[robertlogan.cc](https://robertlogan.cc)

## License

MIT
