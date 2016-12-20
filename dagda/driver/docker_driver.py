import docker


class DockerDriver:

    # -- Public methods

    # DockerDriver Constructor
    def __init__(self):
        super(DockerDriver, self).__init__()
        self.cli = docker.Client(base_url='unix://var/run/docker.sock', version="auto", timeout=3600)

    # Gets the docker image name from a running container
    def get_docker_image_name_from_container_id(self, container_id):
        containers = self.cli.containers(filters={'id': container_id})
        return containers[0]['Image']

    # Checks if docker image is in the local machine
    def is_docker_image(self, image_name):
        image = self.cli.images(name = image_name)
        return len(image) > 0

    # Executes docker exec command and return the output
    def docker_exec(self, container_id, cmd, show_stdout, show_stderr):
        dict = self.cli.exec_create(container=container_id, cmd=cmd, stdout=show_stdout, stderr=show_stderr)
        return (self.cli.exec_start(exec_id=dict.get('Id'))).decode("utf-8", errors="ignore")

    # Gets logs from docker container
    def docker_logs(self, container_id, show_stdout, show_stderr, follow):
        return (self.cli.logs(container=container_id, stdout=show_stdout, stderr=show_stderr, follow=follow))\
               .decode('utf-8')

    # Creates container and return the container id
    def create_container(self, image_name, entrypoint=None, volumes=None, host_config=None):
        container = self.cli.create_container(image=image_name, entrypoint=entrypoint, volumes=volumes,
                                              host_config=host_config)
        return container.get('Id')

    # Docker pull
    def docker_pull(self, image_name):
        self.cli.pull(image_name, tag='latest')

    # Removes the docker image
    def docker_remove_image(self, image_name):
        self.cli.remove_image(image=image_name, force=True)

    # Start container
    def docker_start(self, container_id):
        self.cli.start(container=container_id)

    # Stop container
    def docker_stop(self, container_id):
        self.cli.stop(container=container_id)

    # Gets docker client
    def get_docker_client(self):
        return self.cli
