package platform

const caseInsensitivePaths = true

func classifyPath(p string) PathKind { return classifyWindowsPath(p) }
