// ADAPTADOR DE PAGAMENTO — é aqui que você pluga Asaas, Mercado Pago, Stripe, Pagar.me etc.
//
// createCheckout({ user, plan }) -> deve devolver { url } (página onde o cliente paga).
//   Dica: mande user.id (ou user.email) como "referência externa" para o webhook saber quem pagou.
// parseWebhook(req) -> deve devolver { userId | email, paid: true/false, ref, amount, days }
//   req.body = JSON recebido, req.rawBody = corpo cru (use para validar assinatura do gateway).

exports.createCheckout = async ({ user, plan }) => {
  // Modo simples: link de pagamento fixo criado no painel do gateway (CHECKOUT_URL no .env)
  if (process.env.CHECKOUT_URL) {
    const u = process.env.CHECKOUT_URL;
    return { url: u + (u.includes('?') ? '&' : '?') + 'ref=' + user.id };
  }
  throw new Error('Pagamento ainda não configurado. Fale com o suporte.');
};

// Formato genérico (serve para testar com curl ou ligar via Zapier/Make). Troque pelo formato do seu gateway.
exports.parseWebhook = (req) => {
  const b = req.body || {};
  return { userId: b.userId, email: b.email, paid: b.status === 'paid', ref: b.ref, amount: b.amount, days: b.days };
};
