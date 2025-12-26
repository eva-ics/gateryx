import { useState, useEffect, useReducer, useRef } from "react";
import { engine } from "./components/Engine.tsx";
import ModalDialog from "./components/ModalDialog.tsx";
import { startRegistration } from "@simplewebauthn/browser";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import { copyTextClipboard } from "bmat/dom";

const INVALIDATE_WARN =
  "All sessions including application tokens will be invalidated";

function reloadPage() {
  const url = new URL(window.location.href);
  url.searchParams.set("nocache", Date.now().toString());
  window.location.href = url.toString();
}

interface AppInfo {
  display_name?: string;
  has_icon: boolean;
  name: string;
  allow_tokens: boolean;
  url: string;
}

const AppIcon = ({ app }: { app: AppInfo }) => {
  if (app.has_icon) {
    return (
      <img
        className="app-icon-img"
        src={`${engine.api_uri}/.gateryx/system/app_icon?${app.name}`}
        alt={app.display_name || app.name}
      />
    );
  } else {
    const l = (app.display_name || app.name).toUpperCase().charAt(0);
    return <div className="app-icon-text">{l}</div>;
  }
};

const AudTokenBtn = ({ apps }: { apps: AppInfo[] }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isResultOpen, setIsResultOpen] = useState(false);
  const [appToken, setAppToken] = useState<string | null>(null);
  const inputRef = useRef<HTMLSelectElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [formData, setFormData] = useState<{
    app: string;
    exp: number;
  }>({
    app: "",
    exp: 30
  });

  const issueAudToken = () => {
    if (!formData.app) {
      return;
    }
    engine
      .call("gate.issue_aud_token", {
        app: formData.app,
        exp: formData.exp * 86400
      })
      .then((res) => {
        setIsOpen(false);
        if (!res?.aud_token) {
          setError("Failed to issue application token.");
          return;
        }
        setAppToken(res.aud_token);
        setIsResultOpen(true);
      })
      .catch((e) => {
        setError(e.message || "Failed to issue application token.");
      });
  };

  const issuedTokenForm = (
    <div>
      <div className="success">{success}</div>
      <div className="form-group">
        <label htmlFor="issuedToken">Application Token</label>
        <div style={{ wordBreak: "break-all" }}>
          <small>{appToken}</small>
          <button
            className="btn copy-btn"
            onClick={() => {
              if (appToken) {
                copyTextClipboard(appToken);
                setSuccess("Token copied to clipboard");
              }
            }}
            title="Copy to clipboard"
          >
            <ContentCopyIcon />
          </button>
        </div>
      </div>
      <div className="form-group">
        <small>
          Warning: This token will only be shown once. Make sure to copy and
          store it securely.
        </small>
      </div>
    </div>
  );

  const issueAudTokenForm = (
    <div>
      <div className="error">{error}</div>
      <div className="form-group">
        <label htmlFor="app">Application</label>
        <select
          ref={inputRef}
          id="app"
          name="app"
          className="form-control"
          onChange={(e) => {
            setError(null);
            setFormData({ ...formData, app: e.target.value });
          }}
        >
          <option value="">-- Select an application --</option>
          {apps
            .filter((app) => {
              return app.allow_tokens;
            })
            .map((app, i) => (
              <option key={i} value={app.name}>
                {app.display_name || app.name}
              </option>
            ))}
        </select>
      </div>
      <div className="form-group">
        <label htmlFor="expDays">Expires in (days)</label>
        <input
          type="text"
          id="expDays"
          name="expDays"
          className="form-control"
          value={formData.exp}
          onChange={(e) => {
            setError(null);
            const num = parseInt(e.target.value, 10);
            if (isNaN(num) || num < 0) {
              setError("Expiration must be a positive number.");
              return;
            }
            setFormData({ ...formData, exp: num });
          }}
        />
      </div>
    </div>
  );
  return (
    <>
      <ModalDialog
        title={`Issue application token`}
        content={issueAudTokenForm}
        open={isOpen}
        onClose={() => setIsOpen(false)}
        onConfirm={issueAudToken}
      />
      <ModalDialog
        title={`Application token issued`}
        content={issuedTokenForm}
        open={isResultOpen}
        onClose={() => setIsResultOpen(false)}
      />
      <a
        href="#"
        className="btn outline"
        onClick={() => {
          setError(null);
          setSuccess(null);
          setAppToken(null);
          setIsOpen(true);
          setTimeout(() => {
            inputRef.current?.focus();
          }, 100);
        }}
      >
        Issue app token
      </a>
    </>
  );
};

const ChangePasswordBtn = () => {
  const [isOpen, setIsOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState<{
    currentPassword: string;
    newPassword: string;
    confirmNewPassword: string;
  }>({
    currentPassword: "",
    newPassword: "",
    confirmNewPassword: ""
  });

  const changePassword = () => {
    if (formData.newPassword !== formData.confirmNewPassword) {
      setError("New password and confirmation do not match.");
      return;
    }
    engine
      .call("gate.set_password", {
        old_password: formData.currentPassword,
        new_password: formData.newPassword
      })
      .then(() => {
        setIsOpen(false);
        reloadPage();
      })
      .catch((e) => {
        setError(e.message || "Failed to change password.");
      });
  };

  const changePasswordForm = (
    <div>
      <div className="error">{error}</div>
      <div className="form-group">
        <label htmlFor="currentPassword">Current Password</label>
        <input
          ref={inputRef}
          type="password"
          id="currentPassword"
          name="currentPassword"
          className="form-control"
          onChange={(e) => {
            setError(null);
            setFormData({ ...formData, currentPassword: e.target.value });
          }}
        />
      </div>
      <div className="form-group">
        <label htmlFor="newPassword">New Password</label>
        <input
          type="password"
          id="newPassword"
          name="newPassword"
          className="form-control"
          onChange={(e) => {
            setError(null);
            setFormData({ ...formData, newPassword: e.target.value });
          }}
        />
      </div>
      <div className="form-group">
        <label htmlFor="confirmNewPassword">Confirm New Password</label>
        <input
          type="password"
          id="confirmNewPassword"
          name="confirmNewPassword"
          className="form-control"
          onChange={(e) => {
            setError(null);
            setFormData({ ...formData, confirmNewPassword: e.target.value });
          }}
        />
      </div>
      <div className="form-group">
        <small>Warning: {INVALIDATE_WARN}</small>
      </div>
    </div>
  );
  return (
    <>
      <ModalDialog
        title={`Change password`}
        content={changePasswordForm}
        open={isOpen}
        onClose={() => setIsOpen(false)}
        onConfirm={changePassword}
      />
      <a
        href="#"
        className="btn outline"
        onClick={() => {
          setError(null);
          setIsOpen(true);
          setTimeout(() => {
            inputRef.current?.focus();
          }, 100);
        }}
      >
        Change password
      </a>
    </>
  );
};

const PasskeyBtn = ({
  hasPasskey,
  forcePasskeyUpdate
}: {
  hasPasskey: boolean | null;
  forcePasskeyUpdate: () => void;
}) => {
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const registerPasskey = async () => {
    try {
      const challenge = await engine.call("gate.passkey.register.start");
      const res = await startRegistration(challenge.publicKey);
      await engine.call("gate.passkey.register.finish", res);
      forcePasskeyUpdate();
    } catch (e) {
      console.error("Failed to register passkey:", e);
    }
  };

  const deletePasskey = () => {
    engine
      .call("gate.passkey.delete")
      .then(() => {
        forcePasskeyUpdate();
        setIsDeleteConfirmOpen(false);
      })
      .catch((e) => {
        console.error("Failed to delete passkey:", e);
      });
  };

  if (hasPasskey === null) {
    return <></>;
  }
  if (hasPasskey) {
    return (
      <>
        <ModalDialog
          title={`Delete Passkey`}
          contentText="Are you sure you want to delete your current passkey?"
          open={isDeleteConfirmOpen}
          onClose={() => setIsDeleteConfirmOpen(false)}
          onConfirm={() => {
            deletePasskey();
          }}
        />

        <a
          id="btn_deletePasskey"
          onClick={() => setIsDeleteConfirmOpen(true)}
          href="#"
          className="btn outline"
        >
          Delete passkey
        </a>
      </>
    );
  }
  return (
    <a
      id="btn_registerPasskey"
      onClick={registerPasskey}
      href="#"
      className="btn outline"
    >
      Add a passkey
    </a>
  );
};

const InvalidateBtn = () => {
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);

  const invalidate = () => {
    engine
      .call("gate.invalidate")
      .then(() => {
        setTimeout(() => {
          reloadPage();
        }, 1000);
      })
      .catch((e) => {
        console.error("Failed to delete passkey:", e);
      });
  };

  return (
    <>
      <ModalDialog
        title={`Invalidate`}
        contentText={`${INVALIDATE_WARN}. Are you sure you want to continue?`}
        open={isConfirmOpen}
        onClose={() => setIsConfirmOpen(false)}
        onConfirm={() => {
          invalidate();
        }}
      />

      <a
        id="btn_invalidate"
        onClick={() => setIsConfirmOpen(true)}
        href="#"
        className="btn outline"
      >
        Invalidate
      </a>
    </>
  );
};

export const App = () => {
  //const [appDomain, setAppDomain] = useState<string | null>(null);
  const [apps, setApps] = useState<AppInfo[] | null>(null);
  const [hasPasskey, setHasPasskey] = useState<boolean | null>(null);
  const [force, forcePasskeyUpdate] = useReducer((x) => x + 1, 0);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.has("nocache")) {
      url.searchParams.delete("nocache");
      history.replaceState({}, "", url);
    }
  }, []);

  useEffect(() => {
    engine.call("gate.passkey.present").then((res) => {
      setHasPasskey(res);
    });
  }, [force, setHasPasskey]);

  useEffect(() => {
    fetch(`${engine.api_uri}/.gateryx/system/apps.json`)
      .then((r) => r.json())
      .then((r) => {
        //setAppDomain(r.domain);
        setApps(r.apps);
      })
      .catch(() => {
        setTimeout(() => {
          reloadPage();
        }, 500);
      });
  }, [setApps]);

  const logout = () => {
    engine.call("gate.logout").catch((err) => {
      console.error("Logout failed:", err);
    });
    // reload page after a second
    setTimeout(() => {
      reloadPage();
    }, 1000);
    //let domain = "";
    //if (appDomain) {
    //domain = `; domain=.${appDomain}`;
    //}
    //document.cookie = `${TOKEN_COOKIE_NAME}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/${domain}`;
    //reloadPage();
    return false;
  };

  return (
    <>
      <div id="applist">
        {apps?.map((app, i) => (
          <div className="app" key={i}>
            <a href={app.url}>
              <AppIcon app={app} />
              <div className="app-label">{app.display_name || app.name}</div>
            </a>
          </div>
        ))}
      </div>

      {apps != null ? (
        <>
          <div className="footer">
            <AudTokenBtn apps={apps} />
            <ChangePasswordBtn />
            <PasskeyBtn
              hasPasskey={hasPasskey}
              forcePasskeyUpdate={forcePasskeyUpdate}
            />
          </div>
          <div className="footer">
            <InvalidateBtn />
            <a onClick={logout} href="#" className="btn outline">
              Logout
            </a>
          </div>
        </>
      ) : null}
    </>
  );
};
