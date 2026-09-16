/**
 * UI-only password entropy hint. Not a cryptographic primitive.
 * Never used as an authorization decision.
 */

export function evaluatePasswordStrength(password: string): {
  score: number;
  label: string;
  color: string;
  feedback: string;
} {
  if (!password) {
    return {
      score: 0,
      label: 'Sin contraseña',
      color: 'text-white/40',
      feedback: 'Introduce al menos 8 caracteres',
    };
  }

  let points = 0;
  if (password.length >= 8) points += 1;
  if (password.length >= 14) points += 1;
  if (password.length >= 18) points += 1;
  if (/[A-Z]/.test(password)) points += 1;
  if (/[a-z]/.test(password)) points += 1;
  if (/[0-9]/.test(password)) points += 1;
  if (/[^A-Za-z0-9]/.test(password)) points += 1;

  if (points <= 2 || password.length < 8) {
    return {
      score: 1,
      label: 'Débil',
      color: 'text-red-400',
      feedback: 'Muy vulnerable a ataques de fuerza bruta.',
    };
  }
  if (points <= 4 || password.length < 12) {
    return {
      score: 2,
      label: 'Aceptable',
      color: 'text-amber-400',
      feedback: 'Recomendable añadir símbolos o más longitud.',
    };
  }
  if (points <= 6) {
    return {
      score: 3,
      label: 'Robusta',
      color: 'text-emerald-400',
      feedback: 'Buen nivel de entropía como factor adicional.',
    };
  }
  return {
    score: 4,
    label: 'Alta entropía',
    color: 'text-purple-400',
    feedback: 'La contraseña es un factor adicional; nunca autoriza por sí sola.',
  };
}
