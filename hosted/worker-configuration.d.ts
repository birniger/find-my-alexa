interface Env {
  ASSETS: Fetcher;
  DB: D1Database;
  APP_NAME: string;
  AUTH0_DOMAIN: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_AUDIENCE: string;
  AUTH0_CONNECTION: string;
  OWNER_EMAIL: string;
  REGISTRATION_MODE: "invite-only" | "self-service";
  RUNNER_API_AUDIENCE: string;
  RUNNER_API_TOKEN?: string;
  RUNNER_QUEUE_URL?: string;
  SETUP_QUEUE_URL?: string;
  RUNNER_AWS_REGION?: string;
  RUNNER_AWS_ACCESS_KEY_ID?: string;
  RUNNER_AWS_SECRET_ACCESS_KEY?: string;
  RUNNER_AWS_SESSION_TOKEN?: string;
  SESSION_BUCKET?: string;
  PUBLIC_BASE_URL: string;
  MY_BUILDS_STATUS_TOKEN: string;
  VAPID_PUBLIC_KEY?: string;
  VAPID_PRIVATE_KEY?: string;
  VAPID_SUBJECT?: string;
  EMAIL?: {
    send(message: {
      to: string;
      from: { email: string; name?: string };
      subject: string;
      html: string;
      text: string;
    }): Promise<unknown>;
  };
  EMAIL_FROM?: string;
  EMAIL_FROM_NAME?: string;
}
