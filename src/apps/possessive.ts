/** An app's name with the possessive mark for copy: `Health Log's`, and `Recipes'` for a name that already ends in s. */
export function possessive(name: string): string {
  return /s$/i.test(name) ? `${name}'` : `${name}'s`;
}
