# vendor/hexstrike-ai

Cópia do projeto original, sem nenhuma modificação:

- origem: https://github.com/0x4m4/hexstrike-ai
- commit: `d689933ff579d839c676c82b231f8e98326c5f04` ("readme update")
- licença: MIT — ver `LICENSE` aqui dentro

## Por que está aqui

É a referência. O porte em Rust precisa ser comparado com o que o original faz,
não com o que achamos que ele faz — o servidor desta cópia é o lado Python do
harness de paridade (`migration/docker-compose.yml`).

A árvore `.git` não foi mantida de propósito: um repositório dentro de outro
complica clone, CI e o próprio Delta. Atualizar é apagar a pasta e clonar de
novo no commit desejado, anotando o hash acima.

O código que o porte realmente usa como referência é `migration/hexstrike-ai/`:
a mesma base, reorganizada em pacotes (split 1:1 auditado), que é o que o
harness sobe.
