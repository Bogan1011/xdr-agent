import { createContext, useContext } from "react";
import { Me } from "./api";

export const MeContext = createContext<Me | null>(null);

// useMe is the signed-in console user and their permissions.
export function useMe() {
  return useContext(MeContext);
}
