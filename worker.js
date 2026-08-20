export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET") {
      return Response.json({
        ok: true,
        service: "autofbskuy",
        message: "Auto Feedback Worker is running"
      });
    }

    if (request.method !== "POST") {
      return Response.json(
        { ok: false, error: "POST only" },
        { status: 405 }
      );
    }

    if (!env.BOT_TOKEN || !env.CHAT_ID) {
      return Response.json(
        { ok: false, error: "Missing BOT_TOKEN or CHAT_ID" },
        { status: 500 }
      );
    }

    const form = await request.formData();
    const imageBase64 = form.get("base64_image");
    const caption = String(form.get("caption") || "").slice(0, 1024);

    if (!imageBase64) {
      return Response.json(
        { ok: false, error: "Missing base64_image" },
        { status: 400 }
      );
    }

    let cleanBase64 = String(imageBase64);

    if (cleanBase64.startsWith("data:image/")) {
      const comma = cleanBase64.indexOf(",");
      if (comma !== -1) {
        cleanBase64 = cleanBase64.slice(comma + 1);
      }
    }

    let bytes;

    try {
      const binary = atob(cleanBase64.replace(/\s+/g, ""));
      bytes = new Uint8Array(binary.length);

      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    } catch {
      return Response.json(
        { ok: false, error: "Invalid base64 image" },
        { status: 400 }
      );
    }

    const telegramForm = new FormData();

    telegramForm.append("chat_id", env.CHAT_ID);
    telegramForm.append("caption", caption);

    const blob = new Blob([bytes], {
      type: "image/jpeg"
    });

    telegramForm.append(
      "photo",
      blob,
      "feedback.jpg"
    );

    const tg = await fetch(
      `https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`,
      {
        method: "POST",
        body: telegramForm
      }
    );

    const data = await tg.json();

    if (tg.ok && data.ok) {
      return Response.json({
        ok: true,
        message: "Feedback sent to Telegram"
      });
    }

    return Response.json(
      {
        ok: false,
        error: "Telegram rejected the request",
        telegram: data
      },
      { status: 502 }
    );
  }
};
