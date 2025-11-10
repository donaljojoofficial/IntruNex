<?php

namespace App\Modules\AssetDiscovery\Repository;

use App\Modules\AssetDiscovery\Entity\Asset;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @extends ServiceEntityRepository<Asset>
 *
 * @method Asset|null find($id, $lockMode = null, $lockVersion = null)
 * @method Asset|null findOneBy(array $criteria, array $orderBy = null)
 * @method Asset[]    findAll()
 * @method Asset[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class AssetRepository extends ServiceEntityRepository
{
    private Security $security;

    public function __construct(ManagerRegistry $registry, Security $security)
    {
        parent::__construct($registry, Asset::class);
        $this->security = $security;
    }

    /**
     * Retrieves all assets for the current authenticated user.
     *
     * @return Asset[] Returns an array of Asset objects
     */
    public function findAllForCurrentUser(): array
    {
        $user = $this->security->getUser();
        if (!$user instanceof UserInterface) {
            return [];
        }

        return $this->createQueryBuilder('a')
            ->andWhere('a.user = :user')
            ->setParameter('user', $user)
            ->orderBy('a.userAssetNumber', 'ASC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Retrieves a single asset by ID for the current authenticated user.
     *
     * @param int $id The asset ID
     * @return Asset|null Returns a single Asset object or null
     */
    public function findForCurrentUser(int $id): ?Asset
    {
        $user = $this->security->getUser();
        if (!$user instanceof UserInterface) {
            return null;
        }

        return $this->createQueryBuilder('a')
            ->andWhere('a.id = :id')
            ->andWhere('a.user = :user')
            ->setParameter('id', $id)
            ->setParameter('user', $user)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Retrieves a single asset by criteria for the current authenticated user.
     *
     * @param array $criteria
     * @param array|null $orderBy
     * @return Asset|null Returns a single Asset object or null
     */
    public function findOneByForCurrentUser(array $criteria, array $orderBy = null): ?Asset
    {
        $user = $this->security->getUser();
        if (!$user instanceof UserInterface) {
            return null;
        }

        $criteria['user'] = $user;

        return $this->findOneBy($criteria, $orderBy);
    }

    /**
     * Counts assets for the current authenticated user.
     *
     * @return int
     */
    public function countForCurrentUser(): int
    {
        $user = $this->security->getUser();
        if (!$user instanceof UserInterface) {
            return 0;
        }

        return $this->count(['user' => $user]);
    }

    /**
     * Finds assets by criteria for the current authenticated user.
     *
     * @param array $criteria
     * @param array|null $orderBy
     * @param int|null $limit
     * @param int|null $offset
     * @return Asset[]
     */
    public function findByForCurrentUser(array $criteria, array $orderBy = null, $limit = null, $offset = null): array
    {
        $user = $this->security->getUser();
        if (!$user instanceof UserInterface) {
            return [];
        }

        $criteria['user'] = $user;

        return $this->findBy($criteria, $orderBy, $limit, $offset);
    }
}
