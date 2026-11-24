export function secretReference(
  profile: string | null | undefined,
  name: string,
  redactNames: boolean,
): string | null {
  return profile && name && !redactNames ? `lk://${profile}/${name}` : null;
}
