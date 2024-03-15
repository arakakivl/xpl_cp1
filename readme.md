# CTF: Micro-CMS v2, Moderate
Nota-se uma aplicação web que cria páginas. Aparentemente algumas vulnerabilidades que existiam no antigo sistema foram corrigidas, e um novo sistema de autenticação foi implementado. Por meio da leitura de todas as páginas, não foi possível encontrar nada. Acessar páginas que poderiam estar ocultas não é possível, já que o sistema de autenticação bloqueia esse acesso. Por fim, pôde-se encontrar uma falha possívelmente explorável na página de login de *SQL Injection*.

## Vulnerabilidade número 1: SQL Injection
Uma falha de *SQL injection* é caracterizada pela injeção de caracteres que o SQL trata como especiais, e estes, caso não tratados pelos desenvolvedores do sistema ou pela aplicação que se conecta com o banco, podem permitir leitura e modificação de todos os dados existentes. Além disso, e é o principal forte dessa falha **neste** sistema, permite o *bypass* do sistema de autenticação. Ademais, pôde-se reconhecer a existência da falha ao se inserir caracteres considerados "especiais" pela linguagem de banco de dados utilizada, o que ocasiona um erro na aplicação, como mostra a figura abaixo.
![Falha de SQLi](/images/sqli_proof.png)

### Bruteforce no sistema de autenticação.
Por meio de algumas tentativas falhas de login, percebe-se que não há limite de realização de tentativas de login. Dessa forma, pode-se tentar a sorte com técnicas de bruteforce, para possívelmente encontrar algum usuário.	
Primeiro de tudo, o campo "username": passando como valor `' OR 1=1;--` durante a requisição, obtém-se como resposta que a senha é inválida. Usando qualquer valor no campo de senha, obtém-se como resposta que o usuário não existe -- se nenhum tipo de *SQLi* for injetado no campo de nome de usuário --, e isso é fundamental para nosso *exploit*, já que diferentes respostas aparecem a depender do campo que se "ignora" na *query* SQL. Dessa forma, pode-se obter um usuário e uma senha válida por meio de técnicas de *bruteforce*, além de provavelmente ser possível fazer um *bypass* do sistema de autenticação. As imagens a seguir indicam os diferentes retornos.

![Mensagem que identifica que a senha está inválida](/images/invalid_password_error.png)
![Mensagem que identifica que o nome de usuário está inválido](/images/invalid_username_error.png)

Infelizmente não existe um usuário "admin", como geralmente existe. Por isso, inúmeras requisições serão feitas até encontrar um usuário válido, e vamos fazer isso com a ajuda de ferramentas utilitárias: o `thc-hydra`, passando a mesma senha -- que na consulta SQL será ignorada -- e filtrando pela mensagem que indica um nome de usuário válido ou não. Para isso, o seguinte comando fora utilizado, fazendo o uso de uma *wordlist* de nomes de usuários que pode ser encontrada [aqui](https://github.com/jeanphorn/wordlist/blob/master/usernames.txt).
```sh
# -L indica a wordlist de nomes de usuário, referente ao valor ^USER^.
# -p indica o valor absoluto a ser usado como senha, referente ao valor ^PASS^.
# A opção -t indica o número de threads usado.
# A flag -f é utilizada para parar a execução do bruteforce assim que algum valor válido é encontrado.
hydra -L usernames.txt -t 50 -p "' OR 1=1;--" e5813ef23c0b69101aae5fa4f5bbdaa2.ctf.hacker101.com https-post-form "/login:username=^USER^&password=^PASS^:F=Unknown user" -f
```

Enfim pode-se encontrar o seguinte nome de usuário válido: **hermina**.
Agora um comando similar será utilizado para se encontrar a senha válida desse usuário, como indica a parte do código a seguir:
```sh
hydra -l "' OR 1=1;--" -P /usr/share e5813ef23c0b69101aae5fa4f5bbdaa2.ctf.hacker101.com https-post-form https-post-form "/login:username=^USER^&password=^PASS^:F=Invalid password" -t 50
```

Após obtermos credenciais válidas de acesso, a flag é encontrada, e esta é a terceira flag, como indicam as imagens a seguir:

![Nome de usuário encontrado.](/images/username_found_hydra.png)
![Senha encontrada.](/images/password_found_hydra.png)
![Flag do ataque de bruteforce.](/images/bruteforce_flag.png)

### Fazendo o *bypass* do sistema de autenticação
A primeira consulta que se imagina quando se pensa num sistema de autenticação vulnerável a *SQLi* é a seguinte:
```sql
SELECT * FROM users WHERE username='username' AND password='password';
```
Entretanto, se esta fosse de fato a *query* executada, seria possível fazer o *bypass* do sistema de autenticação com o seguinte *input*: **' OR 1=1--;**, mas não é o que acontece, já que mesmo que se utilize esse valor no campo de usuário, a senha ainda é dita como errada, mas não o usuário -- o que significa que de fato o nome de usuário é "ignorado". O que isso deveria significar? Após um longo tempo de reflexão, pode-se teorizar de que a senha é validada novamente, ou que é validada *somente* depois da consulta, isto é, obtém-se uma conta válida pelo nome de usuário e disso se verifica a senha correta, o que deve significar um algoritmo mais ou menos como o representado da seguinte forma:
```python
# Código que se conecta com o banco de dados e inicializa a variável "db"
def validate_credentials(provided_username, provided_password):
	q = f"SELECT password FROM users WHERE username='{provided_username}';
	user = db.query(q)

	if user:
		return user.password == provided_password
```
Dessa forma, o necessário é fazer com que a senha enviada seja igual a senha verificada, ao passo que se ignora o nome de usuário, o que pode ser atingido com o seguinte valor para o nome de usuário: *anyname' UNION SELECT 'password' AS password FROM admins WHERE 1=1;--*; logo após o *bypass* do sistema de autenticação, pode-se entrar numa página privada e encontrar uma outra flag, como indicam as imagens a seguir.

![Bypass do sistema de autenticação.](/images/auth_bypass.png)
![Flag encontrada após bypass.](/images/bypass_flag.png)

Além do mais, percebe-se que o nome da tabela utilizada mudou; isso ocorreu por meio de tentativa e erro, isto é, as seguintes técnicas ajudaram na identificação da tabela "admins":
 - Descobrimento de quantidade de itens retornados, fazendo uso da *query* **' UNION SELECT NULL;--', onde para cada NULL, um campo teria de ser retornado. Como com mais de um **NULL** um erro na aplicação é gerado, nota-se que a quantidade de campos retornados é apenas um.
 - Identificação do tipo de dado retornado: substituindo NULL por algum valor que é representado por algum tipo de dado, pode-se identificar o tipo de dado, como com a seguinte *query*: ' UNION SELECT 'a';--*.
 - Finalmente, por tentativa e erro, fazendo uso de nomes comuns, identifica-se a tabela **admins**.

## Vulnerabilidade número 2: Broken Access Control
Não é, ou não deveria ser, mais possível editar páginas sem autenticação. Entretanto, fazendo o uso de diferentes tipos de requisições HTTP, percebe-se que mesmo sem estar autenticado, pode-se fazer um POST na rota **/page/edit/numero_da_pagina**, o que deveria ser bloqueado já que não há usuário autenticado; uma falha da implementação do sistema de controle de acesso. Para a exploração da falha, basta fazer uma requisição POST para essa rota, como a imagem a seguir indica.

![Rota de edição de uma página](/images/edit_page_route.png)
![POST na rota de edição de uma página](/images/edit_page_post.png)

## Identificação do relatório
![Id do relatório](/images/id.png)

# Report de vulnerabilidades
As vulnerabilidades encontradas são as de **SQL Injection** e de **Broken Access Control**, ambas que podem causar um impacto absurdo a depender do que podem expor, modificar ou mesmo inviabilizar. Isso porque, a depender da forma que se implementa o sistema todo, ambas podem expor dados -- numa SQLi, retornar dados por meio de ataques com uso da sintaxe de **UNION** por exemplo, e em Broken Access Control, acesso de leitura a coisas que não deveriam ser legíveis --, permitir modificação (novamente por meio da execução de consultas SQL ou acesso não autorizado a recursos que deveriam ser protegidos pela política de controle de acesso do sistema) ou mesmo afetar a avaliabilidade de um sistema -- mais uma vez, com uso de determinados comandos de SQL pode-se fazer com que o banco aguarde antes de retornar algum tipo de dado, por exemplo. Portanto, conclui-se que os pilares fundamentais, **confidencialidade**, **integridade** e **avaliabilidade** podem ser afetados por meio dessas duas vulnerabilidades.

## SQL Injection
### Exemplo de SQL Injection "no mundo real" -- Yahoo!
Em 2013 a corporativa Yahoo! sofreu um ataque de SQLi que expôs inúmeros dados de contas de usuário da empresa. A reputação da empresa desceu lá para baixo, além de sofrer com diversas perdas financeiras. Cerca de três bilhões de contas tiveram seus dados expostos.

### Exemplo de SQL Injection "no mundo real" -- Sony Pictures
Um grupo chamado LulzSec foi o responsável por acessar os dados -- não criptografados -- de cerca de um milhão de pessoas após uma "simples" falha de SQL injection ser explorada. Como sempre, a reputação da empresa caiu, e todos os dados foram expostos.

### Exemplo de código vulnerável - Aplicação Web descrita em Django
```python
# A variável "db" se refere à uma conexão com algum banco de dados SQL. Ela já foi instanciada antes.
# A função "raw_query" executa uma consulta SQL sem nenhum tipo de validação de parâmetros ou de sintaxe.
# A função request.GET.get('id', '') tenta obter algum valor do parâmetro "id", se específicado, durante uma requisição GET.
# O código é vulnerável por permitir o retorno de todos os dados que se quisesse se essa falha fosse explorada.
# Uma maneira de corrigir isso é verificar cada parâmetro que o usuário controla -- ou, quem sabe, não executar consultas puras em SQL, e sim fazer o uso
# de alguma ORM, por exemplo.
provided_id = request.GET.get('id', '')
if provided_id != "":
	query = f"SELECT username, description FROM users WHERE id='provided_id'"
	return db.raw_query(query)

return ""
```

### Exploit 1: Unauthenticated SQL Injection vulnerability - OpenProject 5.0.0 - 8.3.1 - SQL Injection, CVE 2019-11600
Link de referência: https://www.exploit-db.com/exploits/46838

### Exploit 2: Cmaps v8.0 - SQL injection - CVE 2023-29809
Link de referência: https://www.exploit-db.com/exploits/51422

## Broken Access Control
### Exemplo de Broken Access Control "no mundo real" -- Facebook
Uma vulnerabilidade permitia que um usuário comum atribuísse permissões de administrador a ele mesmo para uma determinada página especificada que estivesse no Facebook, apenas por meio da chamada do endpoint `/<page_id>/userpermissions`, por meio de uma requisição POST. Além de não exigir nenhuma técnica particular, o que acontece é que simplesmente, por um mero erro da implementação, um usuário normal pôde virar administrador de qualquer página que quisesse.

### Exemplo de Broken Access Control "no mundo real" -- United States Postal Service (USPS)
Cerca de sessenta milhões de contas foram expostas pois simplesmente qualquer usuário com uma conta ativa no sistema deles poderia verificar **todos** os dados dos outros usuários registrados, incluindo endereços, e-mails, nomes, identificações e números de telefone. Essa falha se encaixa como Broken Access Control pois não exigia técnica ou exploração de alguma vulnerabilidade em si; isto é, não existia intenção da exposição de dado algum, mas a arquitetura do sistema não foi bem implementada e resultou nessa espécie de "vulnerabilidade".

### Exemplo de código vulnerável - API em .NET
```csharp
// Abaixo, um endpoint para a deleção de um usuário.
// Não há nenhum atributo que verifique o usuário que está requisitando essa ação, ou mesmo se ele está autenticado.
// Uma maneira de se contornar isso é usando algum atributo de autenticação, como [HttpAuthorize], por exemplo.
[HttpDelete("{id}")]
public async Task DeleteUser([FromRoute] Guid userId)
{
	try
	{
		var response = await _userService.Delete(userId);
		if (response.Success) return NoContent();

		return response.Error switch {
			Errors.NotFound => NotFound(),
			Errors.BadRequest => BadRequest()
		};
	}
	catch
	{
		return BadRequest();
	}
}
```