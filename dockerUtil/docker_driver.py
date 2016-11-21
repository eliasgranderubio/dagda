import docker


class DockerDriver:

    # -- Public methods

    # DockerDriver Constructor
    def __init__(self):
        super(DockerDriver, self).__init__()
        self.cli = docker.Client(base_url='unix://var/run/docker.sock', version="auto")

    # Gets the docker image name from a running container
    def get_docker_image_name_from_container_id(self, container_id):
        containers = self.cli.containers(filters={'id': container_id})
        return containers[0]['Image']

    # Executes docker exec command and return the stdout
    def docker_exec(self, container_id, cmd):
        dict = self.cli.exec_create(container=container_id, cmd=cmd, stderr=False)
        return (self.cli.exec_start(exec_id=dict.get('Id'))).decode("utf-8", errors="ignore")

    # Creates container and return the container id
    def create_container(self, image_name):
        container = self.cli.create_container(image=image_name)
        return container.get('Id')

    # Start container
    def docker_start(self, container_id):
        self.cli.start(container=container_id)

    # Stop container
    def docker_stop(self, container_id):
        self.cli.stop(container=container_id)
