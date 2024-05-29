package manager

import (
	"context"
	"encoding/json"
	"os"
	"reflect"

	"github.com/go-logr/logr"
	utils "github.com/mvazquezc/acm-certmanager-addon/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	acmclusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	acmclusterv1beta2 "open-cluster-management.io/api/cluster/v1beta2"
	acmconfigpolicyv1 "open-cluster-management.io/config-policy-controller/api/v1"
	acmpolicyv1 "open-cluster-management.io/governance-policy-propagator/api/v1"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

type HubClusterSecretReconciler struct {
	client.Client
	Logger                   logr.Logger
	managedClusterReconciled []string
}

const (
	remediationEnforce         = "Enforce"
	remediationInform          = "Inform"
	complianceTypeMustHave     = "Musthave"
	complianceTypeMustNotHave  = "Mustnothave"
	complianceTypeMustOnlyHave = "Mustonlyhave"
	severityLow                = "Low"
	severityMedium             = "Medium"
	severityHigh               = "High"
	severityCritical           = "Critical"
	policiesNamespace          = "acm-certmanager-addon"
	managedClusterSet          = "global"
)

func NewHubManager() {
	logf.SetLogger(zap.New())

	log := logf.Log.WithName("hub-manager")
	ctrlCacheConfig := cache.Options{
		/* Listen on specific namespace, otherwise all namespaces
		DefaultNamespaces: map[string]cache.Config{
			"open-cluster-management": {},
		},
		*/
	}

	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{Cache: ctrlCacheConfig})

	if err != nil {
		log.Error(err, "could not create manager")
		os.Exit(1)
	}

	// Register ACM Policies types into the mgr
	policySchemeBuilder := &scheme.Builder{GroupVersion: schema.GroupVersion{Group: "policy.open-cluster-management.io", Version: "v1"}}
	policySchemeBuilder.Register(&acmpolicyv1.Policy{}, &acmpolicyv1.PolicyList{}, &acmpolicyv1.PlacementBinding{}, &acmpolicyv1.PlacementBindingList{})
	clusterv1b1SchemeBuilder := &scheme.Builder{GroupVersion: schema.GroupVersion{Group: "cluster.open-cluster-management.io", Version: "v1beta1"}}
	clusterv1b1SchemeBuilder.Register(&acmclusterv1beta1.Placement{}, &acmclusterv1beta1.PlacementList{})
	clusterv1b2SchemeBuilder := &scheme.Builder{GroupVersion: schema.GroupVersion{Group: "cluster.open-cluster-management.io", Version: "v1beta2"}}
	clusterv1b2SchemeBuilder.Register(&acmclusterv1beta2.ManagedClusterSetBinding{}, &acmclusterv1beta2.ManagedClusterSetBindingList{})
	if err := policySchemeBuilder.AddToScheme(mgr.GetScheme()); err != nil {
		log.Error(err, "Couldn't register ACM types into mgr")
		os.Exit(1)
	}
	if err := clusterv1b1SchemeBuilder.AddToScheme(mgr.GetScheme()); err != nil {
		log.Error(err, "Couldn't register ACM types into mgr")
		os.Exit(1)
	}
	if err := clusterv1b2SchemeBuilder.AddToScheme(mgr.GetScheme()); err != nil {
		log.Error(err, "Couldn't register ACM types into mgr")
		os.Exit(1)
	}
	err = builder.
		ControllerManagedBy(mgr). // Create the ControllerManagedBy
		For(&corev1.Secret{}).    // Watch Secrets in the hub
		Complete(&HubClusterSecretReconciler{
			Client: mgr.GetClient(),
			Logger: log,
		})
	if err != nil {
		log.Error(err, "could not create secrets controller")
		os.Exit(1)
	}

	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Error(err, "could not start manager")
		os.Exit(1)
	}
}

func (r *HubClusterSecretReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, req.NamespacedName, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, probably a deletion event...
			r.Logger.Info("Secret not found. Checking if we had it in the policy, otherwise ignore")
			// Check if there is a policy that exists with name certsync-<namespace>
			policyExists, policyObjectFound, err := r.policyExists(ctx, "certsync-"+req.Namespace, policiesNamespace)
			if err != nil {
				return reconcile.Result{}, err
			}
			if policyExists {

				// Check if the deleted secret was defined in the policy and remove it from it
				policyModified, err := r.removeObjectTemplateFromPolicyTemplate(policyObjectFound.Spec.PolicyTemplates[0], req.Name, req.Namespace)
				if err != nil {
					return reconcile.Result{}, err
				}
				if policyModified {
					err = r.Update(ctx, policyObjectFound)
					if err != nil {
						return reconcile.Result{}, err
					}
					r.Logger.Info("Secret removed from the policy")
					return reconcile.Result{}, nil
				}
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	// Check if secret has the certmanager annotations
	if utils.KubeObjectHasAnnotation(secret.Annotations, "cert-manager.io/certificate-name") {
		// Check if namespace where the secret lives is part of a managedcluster
		secretNamespace := &corev1.Namespace{}
		r.Get(ctx, client.ObjectKey{Name: secret.Namespace, Namespace: secret.Namespace}, secretNamespace)
		if err != nil {
			return reconcile.Result{}, err
		}
		if utils.KubeObjectHasLabel(secretNamespace.Labels, "cluster.open-cluster-management.io/managedCluster") {
			// Create a namespace for storing policies if it doesn't exist
			err := r.namespaceForPolicies(ctx, policiesNamespace)
			if err != nil {
				return reconcile.Result{}, err
			}
			// Create managedclustersetbindings for global managedclusterset if it doesn't exist
			err = r.managedClusterSetBindingForPolicies(ctx, managedClusterSet, policiesNamespace)
			if err != nil {
				return reconcile.Result{}, err
			}
			managedClusterName := secretNamespace.Labels["cluster.open-cluster-management.io/managedCluster"]
			r.Logger.Info("Found Secret " + secret.Name + " with the CertManager annotations in the namespace for ManagedCluster " + managedClusterName)
			// Create Placement for destination cluster if it doesn't exist
			err = r.placementForCluster(ctx, managedClusterName, policiesNamespace)
			if err != nil {
				return reconcile.Result{}, err
			}
			// Create a Policy to get this secret synced if it doesn't exist, otherwise make sure it's updated
			policyObjectName, err := r.policyForSecret(ctx, secret, policiesNamespace)
			if err != nil {
				return reconcile.Result{}, err
			}
			//Create a PlacementBinding for the policy if it doesn't exist, then add the policy to the binding
			err = r.placementBindingForClusterAndPolicy(ctx, managedClusterName, policiesNamespace, policyObjectName)
			if err != nil {
				return reconcile.Result{}, err
			}
			//TODO: Create a PolicyCertificate for the namespace where we created the policy if it doesn't exist

			r.Logger.Info("Reconcile finished")
			return reconcile.Result{}, nil
		} else {
			// Secret is not part of a namespace for a managedcluster
			return reconcile.Result{}, nil
		}
	} else {
		// Secret doesn't have certmanager annotation, we don't care about it
		return reconcile.Result{}, nil
	}
}

func (r *HubClusterSecretReconciler) placementBindingForClusterAndPolicy(ctx context.Context, clusterName string, placementNamespace string, policyName string) error {
	placementBinding := &acmpolicyv1.PlacementBinding{}
	placementBinding.Name = clusterName
	placementBinding.Namespace = placementNamespace
	placementBinding.PlacementRef = acmpolicyv1.PlacementSubject{
		APIGroup: "cluster.open-cluster-management.io",
		Kind:     "Placement",
		Name:     clusterName,
	}
	placementBinding.Subjects = []acmpolicyv1.Subject{
		{
			APIGroup: "policy.open-cluster-management.io",
			Kind:     "Policy",
			Name:     policyName,
		},
	}

	placementBindingFound := &acmpolicyv1.PlacementBinding{}
	err := r.Get(ctx, client.ObjectKey{Name: clusterName, Namespace: placementNamespace}, placementBindingFound)
	if err != nil {
		if errors.IsNotFound(err) {
			r.Logger.Info("PlacementBinding " + clusterName + " not found in namespace " + placementNamespace + ". Creating it...")
			err := r.Create(ctx, placementBinding)
			if err != nil {
				return err
			}
			r.Logger.Info("PlacementBinding " + clusterName + " has been created")
			return nil
		} else {
			return err
		}
	}
	// Policy already exist, we want to update it
	r.Logger.Info("PlacementBinding " + clusterName + " found in namespace " + placementNamespace + ". Checking if it needs to be updated...")

	if !reflect.DeepEqual(placementBindingFound.Subjects, placementBinding.Subjects) {
		r.Logger.Info("PlacementBinding " + placementBindingFound.Name + " needs to be updated")
		placementBindingFound.Subjects = placementBinding.Subjects
		err = r.Update(ctx, placementBindingFound)
		if err != nil {
			return err
		}
		r.Logger.Info("PlacementBinding " + placementBindingFound.Name + " has been updated")
	} else {
		r.Logger.Info("PlacementBinding " + placementBindingFound.Name + " is up to date")
	}
	return nil
}

func (r *HubClusterSecretReconciler) placementForCluster(ctx context.Context, clusterName string, placementNamespace string) error {
	placement := &acmclusterv1beta1.Placement{}
	err := r.Get(ctx, client.ObjectKey{Name: clusterName, Namespace: placementNamespace}, placement)
	if err != nil {
		if errors.IsNotFound(err) {
			r.Logger.Info("Placement " + clusterName + " not found in namespace " + placementNamespace + ". Creating it...")
			placement.Name = clusterName
			placement.Namespace = placementNamespace
			placement.Spec = acmclusterv1beta1.PlacementSpec{
				Tolerations: []acmclusterv1beta1.Toleration{
					{
						Key:      "cluster.open-cluster-management.io/unreachable",
						Operator: acmclusterv1beta1.TolerationOpExists,
					},
					{
						Key:      "cluster.open-cluster-management.io/unreachable",
						Operator: acmclusterv1beta1.TolerationOpExists,
					},
				},
				Predicates: []acmclusterv1beta1.ClusterPredicate{
					{
						RequiredClusterSelector: acmclusterv1beta1.ClusterSelector{
							LabelSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{
									"name": clusterName,
								},
							},
						},
					},
				},
			}
			err := r.Create(ctx, placement)
			if err != nil {
				return err
			}
			r.Logger.Info("Placement " + clusterName + " has been created")
		} else {
			return err
		}
	}
	return nil
}

func (r *HubClusterSecretReconciler) managedClusterSetBindingForPolicies(ctx context.Context, managedClusterSetName string, bindingNamespace string) error {
	managedClusterSetBinding := &acmclusterv1beta2.ManagedClusterSetBinding{}
	err := r.Get(ctx, client.ObjectKey{Name: managedClusterSetName, Namespace: bindingNamespace}, managedClusterSetBinding)
	if err != nil {
		if errors.IsNotFound(err) {
			r.Logger.Info("ManagedClusterSetBinding " + managedClusterSetName + " not found in namespace " + bindingNamespace + ". Creating it...")
			managedClusterSetBinding.Name = managedClusterSetName
			managedClusterSetBinding.Namespace = bindingNamespace
			managedClusterSetBinding.Spec.ClusterSet = managedClusterSetName
			err := r.Create(ctx, managedClusterSetBinding)
			if err != nil {
				return err
			}
			r.Logger.Info("ManagedClusterSetBinding " + managedClusterSetName + " has been created")
		} else {
			return err
		}
	}
	return nil
}

func (r *HubClusterSecretReconciler) namespaceForPolicies(ctx context.Context, namespaceName string) error {
	namespace := &corev1.Namespace{}
	err := r.Get(ctx, client.ObjectKey{Name: namespaceName, Namespace: namespaceName}, namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			r.Logger.Info("Namespace " + namespaceName + " for policies, does not exist. Creating it...")
			namespace.Name = namespaceName
			err := r.Create(ctx, namespace)
			if err != nil {
				return err
			}
			r.Logger.Info("Namespace " + namespaceName + " has been created")
		} else {
			return err
		}
	}
	return nil
}

func (r *HubClusterSecretReconciler) addOrUpdateObjectTemplateToPolicyTemplate(policyTemplate *acmpolicyv1.PolicyTemplate, objectTemplate *acmconfigpolicyv1.ObjectTemplate) error {
	r.Logger.Info("Checking if policy template has the required object templates")
	configurationPolicy := &acmconfigpolicyv1.ConfigurationPolicy{}
	err := json.Unmarshal(policyTemplate.ObjectDefinition.Raw, &configurationPolicy)
	if err != nil {
		return err
	}
	genericObjReceived := make(map[string]interface{})
	err = json.Unmarshal(objectTemplate.ObjectDefinition.Raw, &genericObjReceived)
	if err != nil {
		return err
	}
	objReceivedKind := genericObjReceived["kind"].(string)
	objReceivedMetadata := genericObjReceived["metadata"].(map[string]interface{})
	objReceivedName := objReceivedMetadata["name"].(string)
	objReceivedNamespace := objReceivedMetadata["namespace"].(string)

	if len(configurationPolicy.Spec.ObjectTemplates) > 0 {
		r.Logger.Info("PolicyTemplate already has objects in the list, checking if we need to update or add")
		objectFound := false
		for index, obj := range configurationPolicy.Spec.ObjectTemplates {
			genericObjFound := make(map[string]interface{})
			err := json.Unmarshal(obj.ObjectDefinition.Raw, &genericObjFound)
			if err != nil {
				return err
			}
			objFoundKind := genericObjFound["kind"].(string)
			objFoundMetadata := genericObjFound["metadata"].(map[string]interface{})
			objFoundName := objFoundMetadata["name"].(string)
			objFoundNamespace := objFoundMetadata["namespace"].(string)

			if objReceivedKind == objFoundKind && objReceivedName == objFoundName && objReceivedNamespace == objFoundNamespace {
				objectFound = true
				r.Logger.Info("Matching object found, updating existing object template")
				// Update the existing object template if necessary
				configurationPolicy.Spec.ObjectTemplates[index] = objectTemplate
				break
			}
		}
		// Object was not part of the templates, we add it
		if !objectFound {
			r.Logger.Info("No matching object found, adding new object template to the list")
			configurationPolicy.Spec.ObjectTemplates = append(configurationPolicy.Spec.ObjectTemplates, objectTemplate)
		}
		rawConfigurationPolicy, err := json.Marshal(configurationPolicy)
		if err != nil {
			return err
		}
		rawExtension := runtime.RawExtension{
			Raw: rawConfigurationPolicy,
		}
		policyTemplate.ObjectDefinition = rawExtension

	} else {
		r.Logger.Info("PolicyTemplate doesn't have any object definition, adding the object to the list")
		configurationPolicy.Spec.ObjectTemplates = []*acmconfigpolicyv1.ObjectTemplate{objectTemplate}
		rawConfigurationPolicy, err := json.Marshal(configurationPolicy)
		if err != nil {
			return err
		}
		rawExtension := runtime.RawExtension{
			Raw: rawConfigurationPolicy,
		}
		policyTemplate.ObjectDefinition = rawExtension

	}

	return nil
}

func (r *HubClusterSecretReconciler) removeObjectTemplateFromPolicyTemplate(policyTemplate *acmpolicyv1.PolicyTemplate, secretName string, secretNamespace string) (bool, error) {
	r.Logger.Info("Checking if policy template has the required object templates")
	policyTemplateModified := false
	configurationPolicy := &acmconfigpolicyv1.ConfigurationPolicy{}
	err := json.Unmarshal(policyTemplate.ObjectDefinition.Raw, &configurationPolicy)
	if err != nil {
		return policyTemplateModified, err
	}

	objReceivedKind := "Secret"
	objReceivedName := secretName
	objReceivedNamespace := secretNamespace

	if len(configurationPolicy.Spec.ObjectTemplates) > 0 {
		r.Logger.Info("Checking if PolicyTemplate had the deleted secret defined")
		objectFound := false
		for index, obj := range configurationPolicy.Spec.ObjectTemplates {
			genericObjFound := make(map[string]interface{})
			err := json.Unmarshal(obj.ObjectDefinition.Raw, &genericObjFound)
			if err != nil {
				return policyTemplateModified, err
			}
			objFoundKind := genericObjFound["kind"].(string)
			objFoundMetadata := genericObjFound["metadata"].(map[string]interface{})
			objFoundName := objFoundMetadata["name"].(string)
			objFoundNamespace := objFoundMetadata["namespace"].(string)

			if objReceivedKind == objFoundKind && objReceivedName == objFoundName && objReceivedNamespace == objFoundNamespace {
				objectFound = true
				r.Logger.Info("Matching object found, removing existing object from template")
				// Remove object
				configurationPolicy.Spec.ObjectTemplates = append(configurationPolicy.Spec.ObjectTemplates[:index], configurationPolicy.Spec.ObjectTemplates[index+1:]...)
				policyTemplateModified = true
				break
			}
		}
		// Object was not part of the templates, no need to remove anything
		if !objectFound {
			r.Logger.Info("No matching object found, no need to update the policy")
		}
		rawConfigurationPolicy, err := json.Marshal(configurationPolicy)
		if err != nil {
			return policyTemplateModified, err
		}
		rawExtension := runtime.RawExtension{
			Raw: rawConfigurationPolicy,
		}
		policyTemplate.ObjectDefinition = rawExtension
	}

	return policyTemplateModified, nil
}

func (r *HubClusterSecretReconciler) policyExists(ctx context.Context, policyName string, policyNamespace string) (bool, *acmpolicyv1.Policy, error) {
	policyObjectFound := &acmpolicyv1.Policy{}
	err := r.Get(ctx, client.ObjectKey{Name: policyName, Namespace: policyNamespace}, policyObjectFound)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, policyObjectFound, nil
}

func (r *HubClusterSecretReconciler) policyForSecret(ctx context.Context, secretObject *corev1.Secret, policyNamespace string) (string, error) {
	// Cleanup secret
	policySecret := &corev1.Secret{}
	policySecret.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "Secret",
	}
	policySecret.Name = secretObject.Name
	policySecret.Namespace = secretObject.Namespace
	policySecret.Annotations = secretObject.Annotations
	policySecret.Labels = secretObject.Labels
	policySecret.Data = secretObject.Data

	// Check if policy already exists
	policyName := "certsync-" + secretObject.Namespace

	policyExists, policyObjectFound, err := r.policyExists(ctx, policyName, policyNamespace)
	if err != nil {
		return policyName, err
	}
	if !policyExists {
		r.Logger.Info("Policy " + policyName + " not found in namespace " + policyNamespace + ". Creating it...")
		policyObject := &acmpolicyv1.Policy{}
		r.Logger.Info("About to fill policy for secret " + secretObject.Name)
		policyObject.TypeMeta = metav1.TypeMeta{
			APIVersion: "policy.open-cluster-management.io/v1",
			Kind:       "Policy",
		}
		policyObject.Name = policyName
		policyObject.Namespace = policyNamespace
		policyObject.Spec.RemediationAction = remediationInform
		policyObject.Spec.Disabled = false
		// Get objectTemplate for Secret
		secretObjectTemplate, err := objectTemplateForPolicyTemplate(policySecret)
		if err != nil {
			r.Logger.Error(err, "Failed to get a objectTemplate for the policyTemplate")
			return policyName, err
		}
		// We need to send the objectTemplate to the policyTemplate and check if it already exists
		policyTemplate, err := policyTemplateForPolicy(secretObject.Name)
		if err != nil {
			r.Logger.Error(err, "Failed to get a policyTemplate for the policy")
			return policyName, err
		}
		r.addOrUpdateObjectTemplateToPolicyTemplate(policyTemplate, secretObjectTemplate)
		if err != nil {
			r.Logger.Error(err, "Failed to get add objectTemplate for the secret")
			return policyName, err
		}
		policyObject.Spec.PolicyTemplates = []*acmpolicyv1.PolicyTemplate{policyTemplate}
		err = r.Create(ctx, policyObject)
		if err != nil {
			return policyName, err
		}
		r.Logger.Info("Policy " + policyName + " has been created")
		return policyName, nil
	}

	// Policy already exist, we may want to update it
	r.Logger.Info("Policy " + policyName + " found in namespace " + policyNamespace + ". Checking if it needs to be updated...")

	// If we do this, we're copying underlying data thru pointers
	//updatedPolicy := policyObjectFound
	// Create a copy of the current policy found, we will update this copy and compare it at the end of the process
	updatedPolicy, err := deepCopyPolicy(policyObjectFound)
	if err != nil {
		return policyName, err
	}

	// Get objectTemplate for Secret
	secretObjectTemplate, err := objectTemplateForPolicyTemplate(policySecret)
	if err != nil {
		r.Logger.Error(err, "Failed to get a objectTemplate for the policyTemplate")
		return policyName, err
	}
	// Get PolicyTemplate
	r.addOrUpdateObjectTemplateToPolicyTemplate(updatedPolicy.Spec.PolicyTemplates[0], secretObjectTemplate)

	if !reflect.DeepEqual(policyObjectFound.Spec.PolicyTemplates, updatedPolicy.Spec.PolicyTemplates) {
		// Get existing policy with policyTemplates and get them updated
		r.Logger.Info("Policy " + policyName + " needs to be updated")
		policyObjectFound.Spec.PolicyTemplates = updatedPolicy.Spec.PolicyTemplates
		err = r.Update(ctx, policyObjectFound)
		if err != nil {
			return policyName, err
		}
		r.Logger.Info("Policy " + policyName + " has been updated")
	} else {
		r.Logger.Info("Policy " + policyName + " is up to date")
	}
	return policyName, nil
}

func (r *HubClusterSecretReconciler) policyHasSecret(ctx context.Context, secretName string, secretNamespace string) (bool, error) {
	return false, nil
}

func deepCopyPolicy(inputPolicy *acmpolicyv1.Policy) (*acmpolicyv1.Policy, error) {
	bytes, err := json.Marshal(inputPolicy)
	if err != nil {
		return nil, err
	}
	copy := &acmpolicyv1.Policy{}
	err = json.Unmarshal(bytes, copy)
	if err != nil {
		return nil, err
	}

	return copy, nil
}

func policyTemplateForPolicy(policyTemplateName string) (*acmpolicyv1.PolicyTemplate, error) {
	policyTemplate := &acmpolicyv1.PolicyTemplate{}
	configurationPolicy := &acmconfigpolicyv1.ConfigurationPolicy{}
	configurationPolicy.TypeMeta = metav1.TypeMeta{
		APIVersion: "policy.open-cluster-management.io/v1",
		Kind:       "ConfigurationPolicy",
	}
	configurationPolicy.Name = policyTemplateName
	configurationPolicy.Spec = &acmconfigpolicyv1.ConfigurationPolicySpec{
		EvaluationInterval: acmconfigpolicyv1.EvaluationInterval{},
		NamespaceSelector:  acmconfigpolicyv1.Target{},
		RemediationAction:  remediationInform,
		ObjectTemplates:    []*acmconfigpolicyv1.ObjectTemplate{},
		Severity:           severityHigh,
	}

	rawConfigurationPolicy, err := json.Marshal(configurationPolicy)
	if err != nil {
		return nil, err
	}
	rawExtension := runtime.RawExtension{
		Raw: rawConfigurationPolicy,
	}
	policyTemplate.ObjectDefinition = rawExtension
	return policyTemplate, nil
}

func objectTemplateForPolicyTemplate(secretObject *corev1.Secret) (*acmconfigpolicyv1.ObjectTemplate, error) {
	// Marshal secret into a json byte slice
	rawSecret, err := json.Marshal(secretObject)
	if err != nil {
		return nil, err
	}
	rawExtension := runtime.RawExtension{
		Raw: rawSecret,
	}
	objectTemplate := &acmconfigpolicyv1.ObjectTemplate{
		ComplianceType:   complianceTypeMustHave,
		ObjectDefinition: rawExtension,
	}
	return objectTemplate, nil
}
