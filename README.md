# FluxOpen · Painel de auditoria web

Painel **mobile-first, gratuito, open source e self-hosted** para testes de segurança autorizados em sites e APIs. Um cadastro de alvo, um disparo de auditoria, um resultado centralizado por scanner, com exportação JSON e HTML.

## Módulos incluídos

| Ferramenta | Tipo | Função |
| --- | --- | --- |
| ZAP Baseline | conservador | Alertas de segurança web |
| Nuclei | ativo | Templates de vulnerabilidades (taxa reduzida) |
| Subfinder | conservador | Descoberta passiva de subdomínios |
| httpx | conservador | Metadados HTTP |
| Katana | conservador | Crawling superficial limitado ao FQDN |
| FFUF | ativo | Descoberta limitada por wordlist e taxa |
| Feroxbuster | ativo | Descoberta de diretórios com baixa taxa |
| SQLmap | ativo | Testes SQL de baixo nível sobre parâmetros da URL |
| testssl.sh | conservador | Configuração TLS/HTTPS |
| Nikto | ativo | Configuração e vulnerabilidades do servidor |

**Importante:** “conservador” não é sinônimo de ausência de tráfego: ZAP, Katana, httpx e testssl acessam o host. O modo ativo exige confirmação separada. SQLmap será **ignorado** quando a URL não tiver parâmetros de query. Subfinder identifica domínios, mas o sistema não usa os subdomínios encontrados como novos alvos.

## Instalação do painel (self-hosted)

Pré-requisitos: Docker Compose e um servidor Linux (pode ser sua própria máquina ou servidor existente).

1. Clone este repositório.
2. Copie `.env.example` para `.env`.
3. Defina **duas strings aleatórias diferentes** (mínimo 32 caracteres para a assinatura) e uma senha administrativa longa. Sugestão de geração local:
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
4. Inicie o painel:
   ```bash
   docker compose -f compose.yaml up -d --build
   ```
5. Abra `http://localhost:8000` na máquina do servidor e entre com a senha. Para acessar pelo celular, utilize **VPN ou proxy HTTPS autenticado**. Por padrão a porta está deliberadamente vinculada a `127.0.0.1`, não à internet.

### Modo A — Execução no GitHub Actions (sem PC ligado)

Este é o modo padrão do `.env.example`. O painel continua precisando de uma hospedagem própria para autenticação e armazenamento, mas os scanners são executados em runners temporários do GitHub Actions. O uso gratuito está sujeito a limites da plataforma; **não é uma promessa de execuções ilimitadas**.

- `SCAN_BACKEND=github`
- `GH_REPO=nutricionistaalmeidavh-spec/fluxopen`
- `GH_REF=main`
- `GH_TOKEN`: token fine-grained restrito a este repositório, com permissão Actions leitura e escrita; fica **somente no .env do servidor**.
- Configure o **secret de repositório** `SCAN_SIGNING_SECRET` em *GitHub → Settings → Secrets and variables → Actions* com o **mesmo** valor do `.env` (a interface GitHub não deve exibir o valor).
- Ative GitHub Actions se estiver desativado no repositório.

O fluxo é **Painel → autorização assinada → workflow_dispatch → 10 scanners selecionáveis → artefato report.json → painel**. O painel verifica o status e baixa o JSON do artefato depois da execução. No repositório, veja **Actions → FluxOpen · Auditoria autorizada**.

O workflow **recusa disparos diretos sem assinatura HMAC válida**. Cada manifesto é temporário (máximo duas horas) e vincula URL, modo, scanners e ID da auditoria. A autorização registrada no painel precisa estar vigente.

**Privacidade:** este repositório estava **público** na implantação inicial. Para auditar sites de clientes, torne o repositório **privado** antes de executar auditorias reais: nome de URLs, logs, evidências e artefatos podem conter dados sensíveis. Revise as franquias e permissões do GitHub Actions para repositórios privados.

### Modo B — Self-hosted também para os scanners

Configure o painel com Docker Engine no **próprio servidor**, sem depender do GitHub Actions:

```bash
docker compose -f compose.yaml -f compose.local.yaml up -d --build
```

O arquivo `compose.local.yaml` ativa `SCAN_BACKEND=local` e fornece acesso ao Docker do host. **Atenção: montar o socket Docker é privilégio elevado**; não exponha o painel publicamente nem use esse modo em infraestrutura compartilhada. Para ambientes de produção, prefira um worker isolado numa máquina/VM própria, uma rede e Docker rootless.

Os mesmos módulos e limites valem nos dois modos. Todos são gratuitos/open source. O modo local precisa de recursos adequados para executar imagens Docker e instalar os três scanners da imagem auxiliar (`scanner/Dockerfile.misc`).

## Como usar

1. Abra **Alvos autorizados** e informe nome, URL, referência da permissão e sua validade; confirme que o host está dentro do escopo.
2. Em **Visão geral**, selecione um alvo e os scanners. O modo conservador é o padrão.
3. Para usar Nuclei, FFUF, Feroxbuster, SQLmap e Nikto, selecione **Ativo controlado** e confirme a autorização específica.
4. Clique **Disparar auditoria**. Consulte o status e os resultados em **Execuções**. Exporte JSON ou HTML.

## Controles de segurança

- Login por senha de administrador; cookie HttpOnly/SameSite=Strict, token de sessão armazenado somente como hash, proteção CSRF; senha e token GitHub nunca são entregues ao navegador.
- Validação de protocolo, domínio, porta e DNS público no cadastro, no disparo e antes de executar cada scanner. URLs com credenciais, IPs, redes privadas, esquemas não web ou portas arbitrárias são rejeitados.
- Manifestos assinados com HMAC-SHA256: nenhum workflow pode aceitar um alvo ou módulo alterado fora do painel.
- Sem shell sobre URLs (execução por lista de argumentos), limites de concorrência, taxa, memória, CPU, duração e wordlist pequena.
- A descoberta passiva de subdomínios não aumenta automaticamente o escopo.
- Relatórios da auditoria são armazenados em SQLite; os arquivos GitHub Actions expiram após 30 dias por padrão.
- **Limitação operacional:** restrição por hostname e DNS não substitui segmentação de saída de rede. Redirecionamentos, DNS rebinding pós-validação e links externos requerem controles de egress em deployments de alto risco. Execute numa VM isolada, jamais com acesso a redes de produção internas.
- O sistema não verifica juridicamente a autorização; a referência e a confirmação são fornecidas pelo operador.

## Configuração importante

| Variável | Descrição |
| --- | --- |
| `ADMIN_PASSWORD` | Senha única do painel (mín. 12 caracteres) |
| `SCAN_SIGNING_SECRET` | Segredo HMAC (mín. 32 caracteres; também no Actions) |
| `SCAN_BACKEND` | `github` ou `local` |
| `GH_TOKEN` | Token GitHub restrito ao repositório, **somente no servidor** |
| `GH_REPO` / `GH_REF` | Repositório e branch do workflow |
| `COOKIE_SECURE` | Definir `true` atrás de HTTPS |

Teste rápido local (sem escanear sites):
```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q security.py app scanner
```

## Status e limitações

Implementação do painel e integração de execução concluídas no código. Antes do primeiro disparo real é necessário configurar `.env`, criar o secret `SCAN_SIGNING_SECRET` no GitHub e habilitar o runner escolhido. Os testes de código não substituem uma execução real com Docker nem uma revisão de segurança externa. O dashboard não abre scanners em sites públicos por padrão e não fornece garantia de detecção de todas as vulnerabilidades.

## Licença

MIT para o código de integração FluxOpen. As ferramentas de terceiros mantêm suas próprias licenças.
