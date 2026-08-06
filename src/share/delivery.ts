export interface SignedDeliveryAuthorization {
  readonly authorization: unknown;
  readonly proof: unknown;
}

export interface AddressedDeliveryInput {
  readonly credentialsOrigin: string;
  readonly shareUrl: string;
  readonly deliveryAuthorization: SignedDeliveryAuthorization;
  readonly fetchFn?: typeof fetch;
}

export async function requestAddressedDelivery(input: AddressedDeliveryInput): Promise<void> {
  const version = typeof input.deliveryAuthorization.authorization === "object"
    && input.deliveryAuthorization.authorization !== null
    && (input.deliveryAuthorization.authorization as { readonly version?: unknown }).version === 3
    ? 3
    : 2;
  const response = await (input.fetchFn ?? globalThis.fetch)(`${input.credentialsOrigin}/share/v${version}`, {
    method: "POST",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({
      authorization: input.deliveryAuthorization.authorization,
      proof: input.deliveryAuthorization.proof,
      shareUrl: input.shareUrl,
    }),
  });
  if (!response.ok) throw new Error("The invitation request was not accepted. The link above still works.");
}
