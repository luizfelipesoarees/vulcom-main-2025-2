/*
  Este middleware intercepta todas as rotas e verifica
  se um token de autorização foi enviado junto com a
  requisição
*/
import jwt from 'jsonwebtoken'

/*
Vulnerabilidade: API4:2023 - Consumo irrestrito de recursos
Essa vulnerabilidade deveria ter sido evitada no código a partir da adição de um mecanismo de Rate Limiting
antes da execução da lógica de autenticação.
Sem o Rate Limiting, o atacante consegue consumir recursos do servidor, enviando um volume excessivo de requisições,
levando a uma Negação de Serviço e aumentando os custos operacionais.
*/

/*
  Algumas rotas, como POST /users/login, poderão ser
  acessadas sem a necessidade de apresentação do token.
  Cadastramos essas rotas no vetor bypassRoutes.
*/
const bypassRoutes = [
  { url: '/users/login', method: 'POST' },
  // Caso o cadastro de novos usuários seja público
  // { url: '/users', method: 'POST' }  
]

// Função do middleware
export default function(req, res, next) {
  /*
    Verificamos se a rota interceptada corresponde a
    alguma daquelas cadastradas em bypassRoutes. Sendo
    o caso, permite continuar para o próximo middleware
    sem a verificação do token de autorização 
  */
  for(let route of bypassRoutes) {
    if(route.url === req.url && route.method == req.method) {
      next()    // Continua para o próximo middleware
      return    // Encerra este middleware
    }
  }

  /* PROCESSO DE VERIFICAÇÃO DO TOKEN DE AUTORIZAÇÃO */
  let token

  // Primeiramente, procura pelo token de autorização em um cookie
  token = req.cookies[process.env.AUTH_COOKIE_NAME]

  if(! token) {
    // Se não tiver sido encontrado o token no cookie, 
    // procura pelo token no cabeçalho de autorização
    const authHeader = req.headers['authorization']

    console.log({authHeader})

    // Se o cabeçalho 'authorization' não existir, retorna
    // HTTP 403: Forbidden
    if(! authHeader) {
      console.error('ERRO DE AUTORIZAÇÃO: falta de cabeçalho')
      return res.status(403).end()
    }

    /*
      O cabeçalho 'autorization' tem o formato "Bearer XXXXXXXXXXXXXXX",
      onde "XXXXXXXXXXXXXXX" é o token. Portanto, precisamos dividir esse
      cabeçalho (string) em duas partes, cortando onde está o caractere de
      espaço e aproveitando apenas a segunda parte (índice 1)
    */
    token = authHeader.split(' ')[1]
  }

  /*
  Vulnerabilidade: API2:2023 - Falha de autenticação
  Essa vulnerabilidade foi evitada no código pois o token de autorização (JWT) é exigido e validado para as rotas protegidas.
  É verificado se o token existe, no cookie ou no cabeçalho e depois é feita a verificação de integridade e validade com 'jwt.verify'
  e no .env com process.env.TOKEN_SECRET). Isso previne o uso de tokens adulterados e expirados, garantindo que apenas usuários autenticados
  possam realizar alguma ação.
  */

  // Verificação de integridade e validade do token
  jwt.verify(token, process.env.TOKEN_SECRET, (error, user) => {

    // Token inválido ou expirado, retorna
    // HTTP 403: Forbidden
    if(error) {
      console.error('ERRO DE AUTORIZAÇÃO: token inválido ou expirado')
      return res.status(403).end()
    }

    /* 
      Se chegamos até aqui, o token está OK e temos as informações do
      usuário autenticado no parâmetro "user". Vamos guardá-lo dentro
      do objeto "req" para respoder ao front-end sempre que ele perguntar
      qual usuário está atualmente autenticado
    */
    req.authUser = user

    /*
    Vulnerabilidade: API5:2023 - Falha de autenticação a nível de função
    Essa vulnerabilidade poderia ter sido evitada em outras camadas do back-end, no controllers, após esse middleware.
    Nesse caso, ele apenas autentica o usuário, com a função req.authUser = user e não verifica seu nível de autorização, como por exemplo: admin.
    Os controllers que acessam endpoints restritos precisam verificar o campo de função e permissão dentro do req.authUser antes de executar
    a lógica, evitando que usuários comuns acessem funções de alto privilégio/controle.
    */

    // Token verificado e validado, passamos ao próximo middleware
    next()  
  })
}
