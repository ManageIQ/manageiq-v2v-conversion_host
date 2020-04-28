package ovirtprovider

import (
	"context"
	"fmt"
	"time"

	v2vv1alpha1 "github.com/ovirt/v2v-conversion-host/kubevirt-vmware/pkg/apis/v2v/v1alpha1"
	"github.com/ovirt/v2v-conversion-host/kubevirt-vmware/pkg/controller/utils"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const ovirtSecretKey = "ovirt"

var (
	log        = logf.Log.WithName("controller_ovirtprovider")
	timeToWait = time.Duration(5 * time.Minute)
)

// Add creates a new OVirtProvider Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileOVirtProvider{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("ovirtprovider-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// ignore status updates
	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			old := e.ObjectOld.(*v2vv1alpha1.OVirtProvider)
			new := e.ObjectNew.(*v2vv1alpha1.OVirtProvider)
			if old.Status != new.Status {
				// NO enqueue request
				return false
			}
			// ENQUEUE request
			return true
		},
	}

	// Watch for changes to primary resource OVirtProvider
	err = c.Watch(&source.Kind{Type: &v2vv1alpha1.OVirtProvider{}}, &handler.EnqueueRequestForObject{}, p)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileOVirtProvider{}

// ReconcileOVirtProvider reconciles a OVirtProvider object
type ReconcileOVirtProvider struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a OVirtProvider object and makes changes based on the state read
// and what is in the OVirtProvider.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileOVirtProvider) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling OVirtProvider")

	// Fetch the OVirtProvider instance
	instance := &v2vv1alpha1.OVirtProvider{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("The request object cannot be found.")
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		reqLogger.Info("Error reading the request object, requeuing.")
		return reconcile.Result{}, err
	}

	connectionSecret, err := r.fetchSecret(instance)
	if err != nil {
		reqLogger.Error(err, "Failed to get Secret object for the oVirt connection")
		return reconcile.Result{}, err // request will be re-queued
	}
	reqLogger.Info("Connection secret retrieved.")

	r.updateStatusPhase(request, v2vv1alpha1.PhaseConnecting)
	client, err := getClient(context.Background(), connectionSecret)
	if err != nil {
		r.updateStatusPhase(request, v2vv1alpha1.PhaseConnectionFailed)
		return r.checkTime(instance, err)
	}
	defer client.Close()

	if len(instance.Spec.Vms) == 0 { // list of oVirt VMs is requested to be retrieved
		err = r.readVmsList(request, client)
		if err != nil {
			reqLogger.Error(err, "Failed to read list of oVirt VMs.")
			return r.checkTime(instance, err)
		}
	} else {
		// after re-queue when vms updated
		r.updateStatusPhase(request, v2vv1alpha1.PhaseConnectionSuccessful)
	}

	// secret is present, list of VMs is available, let's check for  details to be retrieved
	var lastError error = nil
	for _, vm := range instance.Spec.Vms { // sequential read is probably good enough, just a single VM or a few of them are expected to be retrieved this way
		if vm.DetailRequest {
			err = r.readVMDetail(request, client, &vm)
			if err != nil {
				reqLogger.Error(err, fmt.Sprintf("Failed to read '%s' vm details.", vm.Name))
				lastError = err
			}
		}
	}

	return reconcile.Result{}, lastError
}

func (r *ReconcileOVirtProvider) checkTime(instance *v2vv1alpha1.OVirtProvider, err error) (reconcile.Result, error) {
	diff := time.Now().Sub(instance.CreationTimestamp.Time)
	if diff > timeToWait {
		// do not re-queue
		return reconcile.Result{}, nil
	}
	// wait for user to update the secret
	return reconcile.Result{}, err
}

func (r *ReconcileOVirtProvider) fetchSecret(provider *v2vv1alpha1.OVirtProvider) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: provider.Spec.Connection, Namespace: provider.Namespace}, secret)
	return secret, err
}

func getClient(ctx context.Context, secret *corev1.Secret) (*Client, error) {
	connectionDetails := make(map[string]string)
	err := yaml.Unmarshal(secret.Data[ovirtSecretKey], &connectionDetails)
	if err != nil {
		return nil, err
	}
	return NewClient(ctx, connectionDetails["apiUrl"], connectionDetails["username"], connectionDetails["password"], connectionDetails["caCert"])
}

// read whole list at once
func (r *ReconcileOVirtProvider) readVmsList(request reconcile.Request, client *Client) error {
	log.Info("readVmsList()")

	r.updateStatusPhase(request, v2vv1alpha1.PhaseLoadingVmsList)
	vms, err := client.GetVMs()
	if err != nil {
		r.updateStatusPhase(request, v2vv1alpha1.PhaseLoadingVmsListFailed)
		return err
	}

	err = r.updateVmsList(request, vms, utils.MaxRetryCount)
	if err != nil {
		r.updateStatusPhase(request, v2vv1alpha1.PhaseLoadingVmsListFailed)
		return err
	}

	r.updateStatusPhase(request, v2vv1alpha1.PhaseConnectionSuccessful)
	return nil
}

func (r *ReconcileOVirtProvider) updateVmsList(request reconcile.Request, vms map[string]VM, retryCount int) error {
	instance := &v2vv1alpha1.OVirtProvider{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to get provider object to update list of VMs, intended to write: '%s'", vms))
		if retryCount > 0 {
			utils.SleepBeforeRetry()
			return r.updateVmsList(request, vms, retryCount-1)
		}
		return err
	}

	for vmID, vm := range vms {
		instance.Spec.Vms = append(instance.Spec.Vms, v2vv1alpha1.OVirtVM{
			Name:          vm.Name,
			ID:            vmID,
			ClusterName:   vm.Cluster,
			DetailRequest: false,
		})
	}

	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to update provider object with list of VMs, intended to write: '%s'", vms))
		if retryCount > 0 {
			utils.SleepBeforeRetry()
			return r.updateVmsList(request, vms, retryCount-1)
		}
		return err
	}

	return nil
}

func (r *ReconcileOVirtProvider) readVMDetail(request reconcile.Request, client *Client, vm *v2vv1alpha1.OVirtVM) error {
	log.Info("readVmDetail()")

	r.updateStatusPhase(request, v2vv1alpha1.PhaseLoadingVMDetail)
	vmDetail, err := client.GetVM(vm)
	if err != nil {
		r.updateStatusPhase(request, v2vv1alpha1.PhaseLoadingVMDetailFailed)
		return err
	}

	err = r.updateVMDetail(request, vm, vmDetail, utils.MaxRetryCount)
	if err != nil {
		r.updateStatusPhase(request, v2vv1alpha1.PhaseLoadingVMDetailFailed)
		return err
	}

	r.updateStatusPhase(request, v2vv1alpha1.PhaseConnectionSuccessful)
	return nil
}

func (r *ReconcileOVirtProvider) updateVMDetail(request reconcile.Request, vm *v2vv1alpha1.OVirtVM, vmDetail *v2vv1alpha1.OVirtVMDetail, retryCount int) error {
	instance := &v2vv1alpha1.OVirtProvider{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to get provider object to update detail of '%s' VM.", vm.Name))
		if retryCount > 0 {
			utils.SleepBeforeRetry()
			return r.updateVMDetail(request, vm, vmDetail, retryCount-1)
		}
		return err
	}

	for index, specVM := range instance.Spec.Vms {
		if specVM.ID == vm.ID {
			instance.Spec.Vms[index].DetailRequest = false
			instance.Spec.Vms[index].Detail = *vmDetail
		}
	}

	err = r.client.Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to update provider object with detail of '%s' VM.", vm.Name))
		if retryCount > 0 {
			utils.SleepBeforeRetry()
			return r.updateVMDetail(request, vm, vmDetail, retryCount-1)
		}
		return err
	}

	return nil
}

func (r *ReconcileOVirtProvider) updateStatusPhase(request reconcile.Request, phase v2vv1alpha1.VirtualMachineProviderPhase) {
	log.Info(fmt.Sprintf("updateStatusPhase(): %s", phase))
	r.updateStatusPhaseRetry(request, phase, utils.MaxRetryCount)
}

func (r *ReconcileOVirtProvider) updateStatusPhaseRetry(request reconcile.Request, phase v2vv1alpha1.VirtualMachineProviderPhase, retryCount int) {
	// reload instance to workaround issues with parallel writes
	instance := &v2vv1alpha1.OVirtProvider{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to get provider object to update status info. Intended to write phase: '%s'", phase))
		if retryCount > 0 {
			utils.SleepBeforeRetry()
			r.updateStatusPhaseRetry(request, phase, retryCount-1)
		}
		return
	}

	instance.Status.Phase = phase
	err = r.client.Status().Update(context.TODO(), instance)
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to update provider status. Intended to write phase: '%s'", phase))
		if retryCount > 0 {
			utils.SleepBeforeRetry()
			r.updateStatusPhaseRetry(request, phase, retryCount-1)
		}
	}
}
