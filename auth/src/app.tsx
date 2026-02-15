import { useState, useEffect, useRef, useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import { engine, parse_svc_message } from "./components/Engine.tsx";
//import { cookies } from "bmat/dom";
import type { EngineError, SvcMessage } from "./components/Engine.tsx";

import { startAuthentication } from "@simplewebauthn/browser";
import { QRCodeSVG } from "qrcode.react";

//const TOKEN_COOKIE_NAME = "gateryx_auth_token";

enum AppStateKind {
  LoginForm = "login_form",
  Login = "login"
}

/*
const setToken = (res: any, remember: boolean) => {
  const token = res.token;
  let expires = "";
  if (remember) {
    const expiration = new Date((res.exp + 86400) * 1000).toUTCString();
    expires = `; Expires=${expiration}`;
  }
  let domain = "";
  if (res.domain) {
    domain = `; Domain=${res.domain}`;
  }
  document.cookie = `${TOKEN_COOKIE_NAME}=${token}${expires}${domain}; Path=/; SameSite=Lax`;
  redirectToTarget();
};
*/

const redirectToTarget = () => {
  const params = new URLSearchParams(window.location.search);
  const r = params.get("r");
  const r_decoded = r ? decodeURIComponent(r) : null;
  if (r_decoded) {
    window.location.href = r_decoded;
    return;
  }
  const url = new URL(window.location.href);
  url.searchParams.set("nocache", Date.now().toString());
  window.location.href = url.toString();
};

const fillPasskey = async () => {
  let opts;
  try {
    opts = await engine.call("gate.passkey.auth.start", {});
  } catch (e) {
    console.warn("Passkey auth start failed:", e);
    return;
  }
  console.log("Starting passkey lookup");
  const challenge = opts?.publicKey?.challenge;
  if (!challenge) {
    return;
  }
  const auth = await startAuthentication({
    optionsJSON: opts.publicKey,
    useBrowserAutofill: true
  });
  console.log("Passkey auth:", auth);
  await engine.call("gate.passkey.auth.finish", {
    challenge,
    auth,
    set_auth_cookie: "t"
  });
  redirectToTarget();
};

interface AppState {
  state: AppStateKind;
  err?: EngineError;
  captcha_id?: string;
  otp_requested?: boolean;
  otp_setup_secret?: string;
}

interface FormData {
  username: string;
  password: string;
  remember: boolean;
  captcha_id?: string;
  captcha_str?: string;
  otp?: string;
}

export const App = () => {
  const [app_state, setAppState] = useState<AppState>({
    state: AppStateKind.LoginForm
  });

  const [form, setForm] = useState<FormData>({
    username: "",
    password: "",
    remember: false
  });

  //useEffect(() => {
    //cookies.erase(TOKEN_COOKIE_NAME, "/");
  //}, [app_state, engine]);

  switch (app_state.state) {
    case AppStateKind.Login:
      return (
        <>
          <div className="eva login progress">{"Authenticating..."}</div>
        </>
      );
    default:
      let error_msg = app_state.err?.message;
      return (
        <>
          <CredsForm
            form={form}
            setForm={setForm}
            appState={app_state}
            setAppState={setAppState}
            error_msg={error_msg}
          />
        </>
      );
  }
};

const CredsForm = ({
  form,
  setForm,
  appState,
  setAppState,
  error_msg
}: {
  form: FormData;
  setForm: Dispatch<SetStateAction<FormData>>;
  appState: AppState;
  setAppState: Dispatch<SetStateAction<AppState>>;
  error_msg?: string;
}) => {
  const rememberRef = useRef(false);
  const userRef = useRef<HTMLInputElement | null>(null);
  const otpRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    (userRef.current as HTMLInputElement | null)?.focus();
  }, [setForm]);

  const showOtpInput = appState.otp_requested || appState.otp_setup_secret;
  useEffect(() => {
    if (showOtpInput) {
      otpRef.current?.focus();
    }
  }, [showOtpInput]);

  useEffect(() => {
    fillPasskey()
      .then(() => {
        console.log("Filling passkey user field");
      })
      .catch((err) => {
        if (err.toString().includes("abort signal")) {
          return;
        }
        console.warn("Passkey autofill failed:", err);
        setAppState({
          state: AppStateKind.LoginForm,
          err
        });
      });
  }, [setAppState]);

  const onUpdateField = useCallback(
    (e: any) => {
      const nextFormState = {
        ...form,
        [e.target.name]:
          e.target.name == "remember" ? e.target.checked : e.target.value
      };
      setForm(nextFormState);
      if (e.target.name == "remember") {
        rememberRef.current = e.target.checked;
      }
    },
    [form]
  );

  const onSubmit = useCallback(
    (e: any) => {
      e.preventDefault();
      setAppState({ state: AppStateKind.Login });
      const payload: Record<string, unknown> = {
        user: form.username,
        password: form.password,
        set_auth_cookie: form.remember ? "t" : "u"
      };
      if (form.captcha_id && form.captcha_str) {
        payload.captcha_id = form.captcha_id;
        payload.captcha_str = form.captcha_str;
      }
      if (form.otp !== undefined && form.otp !== "") {
        payload.otp = form.otp;
      }
      engine
        .call("gate.authenticate", payload)
        .then(() => {
          redirectToTarget();
        })
        .catch((err: EngineError) => {
          const process_svg_msg = (sm: SvcMessage) => {
            if (sm.svc == "AUTH") {
              const nextFormState = {
                ...form,
                password: "",
                captcha_id: sm.value,
                captcha_str: ""
              };
              setForm(nextFormState);
              setAppState({
                state: AppStateKind.LoginForm,
                err: {
                  code: -32002,
                  message: "Invalid username or password"
                },
                captcha_id: sm.value
              });
              return;
            }
            if (sm.svc == "CAPTCHA") {
              const nextFormState = {
                ...form,
                captcha_id: sm.value,
                captcha_str: ""
              };
              setForm(nextFormState);
              setAppState({
                state: AppStateKind.LoginForm,
                err: {
                  code: -32003,
                  message: "Invalid CAPTCHA"
                },
                captcha_id: sm.value
              });
              return;
            }
            const nextFormState = {
              ...form,
              captcha_id: sm.value,
              captcha_str: ""
            };
            setForm(nextFormState);
            setAppState({
              state: AppStateKind.LoginForm,
              err: {
                code: -32004,
                message: sm.svc
              },
              captcha_id: sm.value
            });
          };

          if (err.code == -32022) {
            const svc_msg = parse_svc_message(err.message);
            if (
              svc_msg?.kind == "CAPTCHA_REQUIRED" &&
              svc_msg?.message == "CAPTCHA_ID"
            ) {
              process_svg_msg(svc_msg);
            } else if (svc_msg?.kind === "OTP" && svc_msg?.svc === "REQ") {
              setForm({ ...form, otp: "" });
              setAppState({
                state: AppStateKind.LoginForm,
                otp_requested: true
              });
            } else if (svc_msg?.kind === "OTP" && svc_msg?.svc?.startsWith("SETUP=")) {
              setForm({ ...form, otp: "" });
              setAppState({
                state: AppStateKind.LoginForm,
                otp_setup_secret: svc_msg.svc.slice(6)
              });
            } else if (svc_msg?.kind === "OTP" && svc_msg?.svc === "INVALID") {
              setForm({ ...form, otp: "" });
              setAppState({
                state: AppStateKind.LoginForm,
                err: { code: -32022, message: "Invalid OTP code" },
                otp_requested: appState.otp_requested,
                otp_setup_secret: appState.otp_setup_secret
              });
            } else {
              setAppState({ state: AppStateKind.LoginForm, err: err });
            }
          } else {
            setAppState({ state: AppStateKind.LoginForm, err: err });
            const nextFormState = {
              ...form,
              password: ""
            };
            setForm(nextFormState);
          }
        });
    },
    [engine, form]
  );

  const remember = (
    <>
      <div className="eva login row remember">
        <input
          className="eva login checkbox"
          type="checkbox"
          name="remember"
          id="eva_input_remember"
          checked={form.remember}
          onChange={onUpdateField}
        />
        <label htmlFor="eva_input_remember">{"trust this device"}</label>
      </div>
    </>
  );

  let captcha = null;
  if (appState.captcha_id) {
    captcha = (
      <div className="eva login row text">
        <input type="hidden" name="captcha_id" value={form.captcha_id} />
        <label htmlFor="eva_input_captcha">
          <img
            src={`/.gateryx/auth/captcha?${appState.captcha_id}`}
            alt="captcha"
          />
        </label>
        <input
          className="eva login"
          id="eva_input_captcha"
          type="text"
          name="captcha_str"
          value={form.captcha_str}
          onChange={onUpdateField}
        />
      </div>
    );
  }

  let otpBlock = null;
  if (showOtpInput) {
    otpBlock = (
      <>
        {appState.otp_setup_secret ? (
          <div className="eva login row text">
            <label>Two-factor setup</label>
            <div className="eva login otp-setup">
              <p className="eva login otp-setup-hint">
                Scan the QR code with your authenticator app, or enter the secret manually. Then enter the code below.
              </p>
              <div className="eva login otp-setup-qr">
                <QRCodeSVG
                  value={`otpauth://totp/Gateryx:${encodeURIComponent(form.username || "user")}?secret=${encodeURIComponent(appState.otp_setup_secret)}&issuer=Gateryx`}
                  size={180}
                  level="M"
                  includeMargin
                />
              </div>
              <code className="eva login otp-secret" title="TOTP secret">
                {appState.otp_setup_secret}
              </code>
            </div>
          </div>
        ) : null}
        <div className="eva login row text">
          <label htmlFor="eva_input_otp">One-time code</label>
          <input
            ref={otpRef}
            className="eva login"
            id="eva_input_otp"
            type="text"
            name="otp"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="000000"
            value={form.otp ?? ""}
            onChange={onUpdateField}
          />
        </div>
      </>
    );
  }

  let content = (
    <>
      <form className="eva login" onSubmit={onSubmit}>
        <div className="eva login error">{error_msg}</div>
        <div className="eva login row text">
          <label htmlFor="eva_input_user">Login</label>
          <input
            className="eva login"
            id="eva_input_user"
            ref={userRef}
            type="text"
            name="username"
            value={form.username}
            autoComplete="username webauthn"
            onChange={onUpdateField}
          />
        </div>
        <div className="eva login row text">
          <label htmlFor="eva_input_password">Password</label>
          <input
            className="eva login"
            id="eva_input_password"
            type="password"
            name="password"
            autoComplete="current-password"
            value={form.password}
            onChange={onUpdateField}
          />
        </div>
        {captcha}
        {otpBlock}
        {remember}
        <button className="eva login" type="submit">
          Authenticate
        </button>
      </form>
    </>
  );
  return (
    <>
      <LoginForm content={content} />
    </>
  );
};

const LoginForm = ({ content }: { content: JSX.Element }) => {
  return (
    <>
      <div className="eva login container">
        <div className="eva login logo"></div>
        <div className="eva login header"></div>
        <div className="eva login form-container">{content}</div>
      </div>
    </>
  );
};
