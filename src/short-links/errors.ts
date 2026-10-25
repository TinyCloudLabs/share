/** The sealed share is over the one size limit for a link, so no link of any form can carry it. */
export class ShareTooLargeForLink extends Error {
  constructor() {
    super("sealed share is too large for a link");
    this.name = "ShareTooLargeForLink";
  }
}
