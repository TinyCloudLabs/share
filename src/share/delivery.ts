export interface SignedDeliveryAuthorization {
  readonly authorization: unknown;
  readonly proof: unknown;
}

export interface AddressedDeliveryInput {
  readonly emailOrigin: string;
  readonly shareUrl: string;
  readonly deliveryAuthorization: SignedDeliveryAuthorization;
  readonly fetchFn?: typeof fetch;
}

export async function requestAddressedDelivery(input: AddressedDeliveryInput): Promise<void> {
  const response = await (input.fetchFn ?? globalThis.fetch)(`${input.emailOrigin}/share/v2`, {
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
