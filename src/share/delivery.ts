export interface SignedDeliveryAuthorization {
  readonly request: { readonly returnLink: string };
  readonly admission: unknown;
  readonly proof: unknown;
}

export interface AddressedDeliveryInput {
  readonly emailOrigin: string;
  readonly shareUrl: string;
  readonly deliveryAuthorization: SignedDeliveryAuthorization;
  readonly fetchFn?: typeof fetch;
}

export async function requestAddressedDelivery(input: AddressedDeliveryInput): Promise<void> {
  if (input.deliveryAuthorization.request.returnLink !== input.shareUrl) throw new Error("The invitation request is not bound to this share link.");
  const response = await (input.fetchFn ?? globalThis.fetch)(`${input.emailOrigin}/v1/credential-invitations`, {
    method: "POST",
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify(input.deliveryAuthorization),
  });
  if (!response.ok) throw new Error("The invitation request was not accepted. The link above still works.");
}
