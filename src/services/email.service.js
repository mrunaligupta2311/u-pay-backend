function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

export async function sendEmailOtp({ email, otp, fullName }) {
  const apiKey =
    process.env.BREVO_API_KEY ||
    process.env.EMAIL_PROVIDER_API_KEY;

  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || "U-Pay";

  if (!apiKey || !senderEmail) {
    const error = new Error("Email provider configuration is incomplete.");
    error.code = "EMAIL_CONFIG_MISSING";
    throw error;
  }

  const safeName = escapeHtml(fullName);
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "accept": "application/json",
      "api-key": apiKey,
      "content-type": "application/json",
    },
    signal: AbortSignal.timeout(10000),
    body: JSON.stringify({
      sender: {
        name: senderName,
        email: senderEmail,
      },
      to: [{ email }],
      subject: "Your U-Pay verification code",
      textContent:
        `Hello ${fullName}, your U-Pay verification code is ${otp}. ` +
        "It expires in 5 minutes. Do not share this code with anyone.",
      htmlContent: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px">
          <h2>Verify your U-Pay account</h2>
          <p>Hello ${safeName},</p>
          <p>Use this verification code to continue your registration:</p>
          <div style="font-size:30px;font-weight:bold;letter-spacing:8px;padding:16px 0">
            ${otp}
          </div>
          <p>This code expires in 5 minutes.</p>
          <p>Do not share this code with anyone.</p>
          <p>If you did not request this code, you can ignore this email.</p>
        </div>
      `,
    }),
  });

  if (!response.ok) {
    let providerStatus = response.status;
    let providerCode = "UNKNOWN";
    let providerMessage = "No provider details available.";

    try {
      const details = await response.json();

      if (typeof details.code === "string") {
        providerCode = details.code.slice(0, 100);
      }

      if (typeof details.message === "string") {
        providerMessage = details.message.slice(0, 300);
      }
    } catch {
      // Keep safe fallback details if the response is not JSON.
    }

    console.error("Brevo email request rejected:", {
      status: providerStatus,
      code: providerCode,
      message: providerMessage,
    });

    const error = new Error("Email provider rejected the request.");
    error.code = "EMAIL_DELIVERY_FAILED";
    throw error;
  }
}
