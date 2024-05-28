package utils

func Contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func RemoveStringFromSlice(slice []string, s string) []string {
	for i, v := range slice {
		if v == s {
			slice = append(slice[:i], slice[i+1:]...)
			break
		}
	}
	return slice
}

func KubeObjectHasLabel(labels map[string]string, label string) bool {
	_, exists := labels[label]
	return exists
}

func KubeObjectHasAnnotation(labels map[string]string, label string) bool {
	_, exists := labels[label]
	return exists
}
