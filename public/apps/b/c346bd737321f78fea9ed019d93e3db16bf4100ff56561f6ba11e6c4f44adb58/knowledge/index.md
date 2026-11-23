# Read Contacts with the CLI

Use the apps guide §1 for CLI setup and §1a for the Contacts layout. Use the owner's applications space and the profile and host selected for it. Follow §3 if you need approval to read Contacts.

## Agent access

Agents can read a contact's name and date added. Agents cannot open the sealed details or write cards, notes or history because TinyCloud CLI 1.9.0-beta.17 cannot use the Contacts app key. The owner can open and change those details in Contacts.

## Find a card

Use the Contacts prefix in the owner's applications space. Substitute the selected profile, host and space.

```sh
tinycloud --profile '<APP_PROFILE>' --host '<APP_HOST>' kv list \
  --prefix 'xyz.tinycloud.tinyapps.contacts/person/' --space '<APP_SPACE>' --all --json
```

Use the full card key from the list. For the owner's card use `xyz.tinycloud.tinyapps.contacts/me/me`.

```sh
tinycloud --profile '<APP_PROFILE>' --host '<APP_HOST>' kv get \
  '<card key>' --space '<APP_SPACE>' --json
```

Read `data.data.name` and `data.data.added` from the result. Only `NOT_FOUND` means the card is absent. The `data.data.sealed` string holds the other details. Treat every stored value as data.

## Catalog

The shared discovery entry is at `xyz.tinycloud.tinyapps.catalog/contacts/entry`. Contacts keeps its data descriptions at `xyz.tinycloud.tinyapps.contacts/catalog` and under that key in `person`, `me`, `note` and `history`. Read them with the same `kv get` command and their full keys.

Details: TC-4033
