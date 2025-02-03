<?php

namespace App\Controller\Admin;

use App\Entity\Users;
use App\Repository\UsersRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/admin/utilisateurs', name: 'admin_users_')]
class UsersController extends AbstractController
{
    #[Route('/', name: 'index')]
    public function index(UsersRepository $usersRepository): Response
    {
        $users = $usersRepository->findBy([], ['firstname' => 'asc']);
        return $this->render('admin/users/index.html.twig', compact('users'));
    }

    #[Route('/add-admin/{id}', name: 'add_admin', methods: ['POST'])]
    public function addAdmin(Users $user, EntityManagerInterface $em, Request $request): RedirectResponse
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if ($this->isCsrfTokenValid('add_admin' . $user->getId(), $request->request->get('_token'))) {
            $roles = $user->getRoles();
            if (!in_array('ROLE_ADMIN', $roles)) {
                $roles[] = 'ROLE_ADMIN';
                $user->setRoles($roles);
                $em->flush();
                $this->addFlash('success', 'L\'utilisateur a été promu administrateur.');
            }
        } else {
            $this->addFlash('error', 'Token CSRF invalide.');
        }

        return $this->redirectToRoute('admin_users_index');
    }

    #[Route('/remove-admin/{id}', name: 'remove_admin', methods: ['POST'])]
    public function removeAdmin(Users $user, EntityManagerInterface $em, Request $request): RedirectResponse
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if ($this->isCsrfTokenValid('remove_admin' . $user->getId(), $request->request->get('_token'))) {
            $roles = $user->getRoles();
            if (in_array('ROLE_ADMIN', $roles)) {
                $roles = array_diff($roles, ['ROLE_ADMIN']);
                $user->setRoles(array_values($roles));
                $em->flush();
                $this->addFlash('success', 'Les privilèges administrateur ont été retirés.');
            }
        } else {
            $this->addFlash('error', 'Token CSRF invalide.');
        }

        return $this->redirectToRoute('admin_users_index');
    }

    #[Route('/delete/{id}', name: 'delete', methods: ['POST'])]
    public function delete(Users $user, EntityManagerInterface $em, Request $request): RedirectResponse
    {
        $this->denyAccessUnlessGranted('ROLE_ADMIN');

        if ($this->isCsrfTokenValid('delete_user' . $user->getId(), $request->request->get('_token'))) {
            $em->remove($user);
            $em->flush();
            $this->addFlash('success', 'L\'utilisateur a été supprimé avec succès.');
        } else {
            $this->addFlash('error', 'Token CSRF invalide.');
        }

        return $this->redirectToRoute('admin_users_index');
    }
}
