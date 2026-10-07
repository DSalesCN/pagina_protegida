// ============================================================
// CONFIGURAÇÃO DA PÁGINA PROTEGIDA v2
// ============================================================

// Texto utilizado para gerar o token da sessão.
const TEXTO_SESSAO = "pagina-protegida-auth";

// Tempo da sessão.
// 8 horas = 28800 segundos.
const TEMPO_SESSAO = 28800;


// ============================================================
// FUNÇÃO PRINCIPAL
// ============================================================

export async function onRequest(context) {

    // Obtém a requisição recebida pelo navegador.
    const request = context.request;

    // Obtém as variáveis/segredos configurados no Cloudflare.
    const env = context.env;

    // Descobre o método utilizado.
    const metodo = request.method;

    // ========================================================
    // REQUISIÇÃO GET
    // ========================================================

    if (metodo === "GET") {

        // Verifica se o navegador já possui um cookie válido.
        const autenticado = await verificarSessao(request, env);

        // Se estiver autenticado...
        if (autenticado) {

            // Mostra a página azul.
            return respostaBemVindo();

        }

        // Caso não esteja autenticado...
        // Mostra a tela de senha.
        return respostaLogin();

    }


    // ========================================================
    // REQUISIÇÃO POST
    // ========================================================

    if (metodo === "POST") {

        // Lê os dados enviados pelo formulário.
        const dados = await request.formData();

        // Obtém o campo chamado "senha".
        const senhaDigitada = dados.get("senha");


        // ====================================================
        // VERIFICA A SENHA
        // ====================================================

        if (
            typeof senhaDigitada === "string" &&
            senhaDigitada === env.SENHA
        ) {

            // Cria um token de sessão.
            const token = await criarToken(env.SENHA);

            // Redireciona para a página principal.
            return new Response(null, {

                // Código 303 = redirecionamento após POST.
                status: 303,

                headers: {

                    // Volta para a página inicial.
                    "Location": "/",

                    // Cria o cookie de autenticação.
                    "Set-Cookie":
                        `sessao=${token}; ` +
                        `Path=/; ` +
                        `Max-Age=${TEMPO_SESSAO}; ` +
                        `HttpOnly; ` +
                        `Secure; ` +
                        `SameSite=Strict`
                }

            });

        }


        // ====================================================
        // SENHA INCORRETA
        // ====================================================

        return respostaLogin("Senha incorreta.");

    }


    // ========================================================
    // MÉTODO NÃO PERMITIDO
    // ========================================================

    return new Response("Método não permitido.", {

        status: 405,

        headers: {
            "Allow": "GET, POST"
        }

    });

}


// ============================================================
// TELA DE LOGIN
// ============================================================

function respostaLogin(erro = "") {

    // Mensagem de erro.
    const mensagemErro = erro
        ? `<div class="erro">${erro}</div>`
        : "";


    // HTML da tela de login.
    const html = `

<!DOCTYPE html>

<html lang="pt-BR">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Acesso</title>


    <style>

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }


        html,
        body {

            width: 100%;
            height: 100%;

            font-family: Arial, sans-serif;

        }


        body {

            background-color: #f2f2f2;

            display: flex;

            justify-content: center;

            align-items: center;

        }


        .login {

            width: 350px;

            padding: 35px;

            background-color: white;

            border-radius: 12px;

            box-shadow:
                0 5px 25px rgba(0, 0, 0, 0.15);

            text-align: center;

        }


        h1 {

            margin-bottom: 25px;

            font-size: 28px;

        }


        input {

            width: 100%;

            padding: 13px;

            margin-bottom: 15px;

            border: 1px solid #ccc;

            border-radius: 6px;

            font-size: 16px;

        }


        button {

            width: 100%;

            padding: 13px;

            border: none;

            border-radius: 6px;

            background-color: #0066ff;

            color: white;

            font-size: 16px;

            font-weight: bold;

            cursor: pointer;

        }


        button:hover {

            background-color: #0052cc;

        }


        .erro {

            margin-bottom: 15px;

            color: red;

            font-size: 14px;

        }

    </style>

</head>


<body>


    <div class="login">

        <h1>Acesso</h1>

        ${mensagemErro}


        <form method="POST">

            <input
                type="password"
                name="senha"
                placeholder="Digite a senha"
                required
                autofocus
            >


            <button type="submit">
                ENTRAR
            </button>

        </form>

    </div>


</body>

</html>

`;


    return new Response(html, {

        status: 200,

        headers: {

            "Content-Type": "text/html; charset=UTF-8",

            "Cache-Control": "no-store"

        }

    });

}


// ============================================================
// PÁGINA BEM-VINDO
// ============================================================

function respostaBemVindo() {

    const html = `

<!DOCTYPE html>

<html lang="pt-BR">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>Bem-vindo</title>


    <style>

        * {

            margin: 0;

            padding: 0;

            box-sizing: border-box;

        }


        html,
        body {

            width: 100%;

            height: 100%;

        }


        body {

            overflow: hidden;

        }


        .pagina {

            width: 100vw;

            height: 100vh;

            background-color: blue;

            display: flex;

            justify-content: center;

            align-items: center;

        }


        .mensagem {

            color: white;

            font-family: Arial, sans-serif;

            font-size: 50px;

            font-weight: bold;

        }

    </style>

</head>


<body>


    <div class="pagina">

        <div class="mensagem">

            BEM-VINDO

        </div>

    </div>


</body>

</html>

`;


    return new Response(html, {

        status: 200,

        headers: {

            "Content-Type": "text/html; charset=UTF-8",

            "Cache-Control": "no-store"

        }

    });

}


// ============================================================
// CRIA TOKEN DA SESSÃO
// ============================================================

async function criarToken(senha) {

    // Cria uma chave criptográfica usando a senha.
    const chave = await crypto.subtle.importKey(

        "raw",

        new TextEncoder().encode(senha),

        {
            name: "HMAC",
            hash: "SHA-256"
        },

        false,

        ["sign"]

    );


    // Gera uma assinatura criptográfica.
    const assinatura = await crypto.subtle.sign(

        "HMAC",

        chave,

        new TextEncoder().encode(TEXTO_SESSAO)

    );


    // Converte o resultado para Base64.
    return btoa(
        String.fromCharCode(...new Uint8Array(assinatura))
    );

}


// ============================================================
// VERIFICA SESSÃO
// ============================================================

async function verificarSessao(request, env) {

    // Obtém o cookie enviado pelo navegador.
    const cookies = request.headers.get("Cookie") || "";


    // Procura o cookie "sessao".
    const encontrado = cookies.match(
        /(?:^|;\s*)sessao=([^;]+)/
    );


    // Se não existir cookie...
    if (!encontrado) {

        return false;

    }


    // Token armazenado no navegador.
    const tokenRecebido = encontrado[1];


    // Gera novamente o token correto.
    const tokenCorreto = await criarToken(env.SENHA);


    // Compara os dois tokens.
    return tokenRecebido === tokenCorreto;

}
