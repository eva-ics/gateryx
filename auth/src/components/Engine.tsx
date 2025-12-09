const isDev = import.meta.env.MODE === "development";

const RPC_URI = "/.gateryx/rpc";

export interface SvcMessage {
  kind: string;
  svc: string;
  message?: string;
  value?: string;
}

export const parse_svc_message = (msg?: string): SvcMessage | null => {
  if (msg && msg.startsWith("|")) {
    let sp = msg.split("|");
    let kind = sp[1];
    if (kind) {
      let result: SvcMessage = { kind: kind, svc: sp[2] };
      let svc_msg = sp[3];
      if (svc_msg) {
        let sp_msg = svc_msg.split("=");
        result.message = sp_msg[0];
        result.value = sp_msg[1];
      }
      return result;
    }
  }
  return null;
};

export interface EngineError {
  code: number;
  message: string;
}

export class Engine {
  api_uri: string;
  rpc_call_id;
  constructor() {
    this.api_uri = isDev ? "http://127.0.0.1:3000" : "";
    this.rpc_call_id = 0;
  }
  call(method: string, params?: any): Promise<any> {
    let me = this;
    return new Promise((resolve, reject) => {
      const headers: any = {
        "Content-Type": "application/json"
      };
      const call_id = me.rpc_call_id;
      fetch(`${me.api_uri}${RPC_URI}`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: call_id,
          method: method,
          params: params || null
        })
      })
        .then((response) => {
          if (response.ok) {
            response
              .json()
              .then((data) => {
                if (!data || typeof data !== "object") {
                  reject({ code: -32010, message: "Invalid server response" });
                  return;
                }
                if (data.jsonrpc !== "2.0") {
                  reject({ code: -32010, message: "Invalid server response" });
                  return;
                }
                if (data.id !== call_id) {
                  reject({ code: -32010, message: "Invalid server response" });
                  return;
                }
                if (data.error) {
                  reject(data.error);
                  return;
                }
                resolve(data.result === undefined ? null : data.result);
              })
              .catch(() => {
                reject({ code: -32010, message: "Invalid server response" });
              });
          } else {
            reject({ code: -32010, message: "Server error" });
          }
        })
        .catch(() => {
          reject({ code: -32010, message: "Server unavailable" });
        });
    });
  }
}

export const engine = new Engine();

export const EngineErrorMessage = ({
  error,
  className
}: {
  error?: EngineError;
  className?: string;
}) => {
  return (
    <div className={`eva-error ${className || ""}`}>
      {error
        ? "Error" +
          (error.message ? ": " + error.message : "") +
          ` (${error.code})`
        : ""}
    </div>
  );
};
