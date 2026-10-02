// What is left at the old address after Device Finder moved to a hostname that
// says what it is. It holds nothing — no bindings, no secrets, no database —
// and exists only so that bookmarks, the Alexa app's stored link, and any
// password link already sent by email land somewhere useful instead of 404ing.
//
// 308 rather than 302: the method and body survive, so a POST that was aimed
// here still arrives intact. Delete this Worker once nothing reaches it.

const TARGET = "https://device-finder.birniger.workers.dev";

const worker = {
  async fetch(request: Request): Promise<Response> {
    const from = new URL(request.url);
    const to = new URL(from.pathname + from.search, TARGET);
    return new Response(null, {
      status: 308,
      headers: {
        location: to.toString(),
        "cache-control": "no-store",
      },
    });
  },
} satisfies ExportedHandler;

export default worker;
