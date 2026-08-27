// trigger deploy
export default {
  async fetch(request, env) {
    console.log("[AUTOFB] ===== REQUEST START =====");
    console.log("[AUTOFB] Method:", request.method);
    console.log("[AUTOFB] URL:", request.url);

    try {
      if (request.method === "GET") {
        console.log("[AUTOFB] Health check GET");

        return Response.json({
          ok: true,
          status: true,
          service: "autofbskuy",
          message: "Auto Feedback Worker is running"
        });
      }

      if (request.method !== "POST") {
        console.log("[AUTOFB] Ditolak: bukan POST");

        return Response.json(
          {
            ok: false,
            status: false,
            error: "POST only"
          },
          { status: 405 }
        );
      }

      // Jangan tampilkan isi token ke log
      console.log(
        "[AUTOFB] BOT_TOKEN tersedia:",
        !!env.BOT_TOKEN
      );

      console.log(
        "[AUTOFB] CHAT_ID tersedia:",
        !!env.CHAT_ID
      );

      if (!env.BOT_TOKEN || !env.CHAT_ID) {
        console.error("[AUTOFB] BOT_TOKEN / CHAT_ID belum tersedia");

        return Response.json(
          {
            ok: false,
            status: false,
            error: "Missing BOT_TOKEN or CHAT_ID"
          },
          { status: 500 }
        );
      }

      console.log("[AUTOFB] Membaca POST form...");

      const form = await request.formData();

      const imageBase64 = form.get("base64_image");
      const caption =
        String(form.get("caption") || "").slice(0, 1024);

      console.log(
        "[AUTOFB] base64_image tersedia:",
        !!imageBase64
      );

      console.log(
        "[AUTOFB] Caption length:",
        caption.length
      );

      if (!imageBase64) {
        console.error("[AUTOFB] base64_image tidak ditemukan");

        return Response.json(
          {
            ok: false,
            status: false,
            error: "Missing base64_image"
          },
          { status: 400 }
        );
      }

      let cleanBase64 = String(imageBase64);

      console.log(
        "[AUTOFB] Base64 length:",
        cleanBase64.length
      );

      if (cleanBase64.startsWith("data:image/")) {
        const comma = cleanBase64.indexOf(",");

        if (comma !== -1) {
          cleanBase64 = cleanBase64.slice(comma + 1);
        }
      }

      let bytes;

      try {
        const binary = atob(
          cleanBase64.replace(/\s+/g, "")
        );

        bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }

        console.log(
          "[AUTOFB] Decode Base64 OK. Image bytes:",
          bytes.length
        );

      } catch (err) {
        console.error(
          "[AUTOFB] Decode Base64 gagal:",
          String(err)
        );

        return Response.json(
          {
            ok: false,
            status: false,
            error: "Invalid base64 image"
          },
          { status: 400 }
        );
      }

      const telegramForm = new FormData();

      telegramForm.append(
        "chat_id",
        env.CHAT_ID
      );

      telegramForm.append(
        "caption",
        caption
      );

      const blob = new Blob(
        [bytes],
        {
          type: "image/jpeg"
        }
      );

      telegramForm.append(
        "photo",
        blob,
        "feedback.jpg"
      );

      console.log("[AUTOFB] Mengirim foto ke Telegram...");

      const tg = await fetch(
        `https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`,
        {
          method: "POST",
          body: telegramForm
        }
      );

      console.log(
        "[AUTOFB] Telegram HTTP status:",
        tg.status
      );

      const data = await tg.json();

      console.log(
        "[AUTOFB] Telegram ok:",
        data?.ok === true
      );

      if (tg.ok && data.ok) {
        console.log("[AUTOFB] ✅ FEEDBACK BERHASIL");

        return Response.json({
          ok: true,
          status: true,
          message: "Feedback sent to Telegram"
        });
      }

      console.error(
        "[AUTOFB] ❌ Telegram menolak request:",
        JSON.stringify(data)
      );

      return Response.json(
        {
          ok: false,
          status: false,
          error: "Telegram rejected the request",
          telegram: data
        },
        { status: 502 }
      );

    } catch (err) {
      console.error(
        "[AUTOFB] ❌ WORKER ERROR:",
        String(err)
      );

      return Response.json(
        {
          ok: false,
          status: false,
          error: String(err)
        },
        { status: 500 }
      );

    } finally {
      console.log("[AUTOFB] ===== REQUEST END =====");
    }
  }
};
